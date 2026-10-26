"""The token contract, as the LMS API checks it.

A copy of the LMS repo's packages/authz/src/vetfab_authz/tokens.py (canonical there), kept verbatim apart from this
header so these tests prove every token the service mints is one the LMS would accept. See CONTRACT.md: when the
contract changes, change it in both places.
"""

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import httpx
import jwt
from jwt import PyJWK

ALGORITHMS = ["RS256"]
# RFC 9068 access-token type. Refresh tokens, ID tokens and other JWTs signed by
# the same key must carry a different `typ` and are rejected here.
ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})
# A token whose `kid` is unknown triggers at most one JWKS refetch per interval,
# so random kids cannot turn the API into a JWKS request amplifier.
MIN_REFETCH_SECONDS = 30
MAX_TOKEN_LENGTH = 8192
MAX_JWKS_BYTES = 65_536


class InvalidTokenError(Exception):
    """The bearer token is missing, malformed, expired or not ours. Maps to 401."""


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    user_id: UUID
    expires_at: int


@dataclass(frozen=True, slots=True)
class JwksSource:
    """Where signing keys come from: the identity service's JWKS URL, or a local file (development/test)."""

    url: str | None = None
    file: Path | None = None
    # Refresh keys this often while things are healthy.
    cache_seconds: int = 300
    # Stop trusting cached keys this long after the last successful fetch.
    max_stale_seconds: int = 3600
    # Upper bound on one whole JWKS fetch (connect + all reads). httpx timeouts
    # apply per read, so a slow-drip response could otherwise hold the refresh
    # lock indefinitely (security re-verification L-new-1).
    fetch_deadline_seconds: float = 10.0

    def __post_init__(self) -> None:
        if (self.url is None) == (self.file is None):
            raise ValueError("JwksSource needs exactly one of url or file")


@dataclass(frozen=True, slots=True)
class TokenPolicy:
    issuer: str
    audience: str
    leeway_seconds: int = 30
    # Plan §28: 15-minute access tokens. A longer-lived token is not an access token.
    max_lifetime_seconds: int = 900


class JwksError(Exception):
    """The JWKS document could not be fetched or contained no usable key."""


class JwksKeyStore:
    """Caches the identity service's signing keys.

    Security review M-1:
    * at most one fetch per MIN_REFETCH_SECONDS, whether the last attempt
      failed or a token named an unknown `kid`, so an outage or random kids
      cannot queue requests behind serial fetches;
    * while a refresh is in flight, requests with a known `kid` use the cached
      key instead of waiting;
    * keys older than `max_stale_seconds` since the last successful fetch are
      no longer trusted, so a rotated-out key does not stay valid forever
      while the endpoint is unreachable;
    * malformed or oversized documents are errors (401), never 500, and one
      bad JWK does not discard the good ones.
    """

    def __init__(
        self,
        source: JwksSource,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source = source
        self._http = http
        self._clock = clock
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._lock = asyncio.Lock()

    def _age(self, now: float) -> float:
        return float("inf") if self._fetched_at is None else now - self._fetched_at

    async def _load(self) -> bytes:
        if self._source.file is not None:
            data = self._source.file.read_bytes()
        else:
            assert self._source.url is not None
            client = self._http or httpx.AsyncClient(timeout=5.0)
            try:
                async with client.stream("GET", self._source.url) as response:
                    response.raise_for_status()
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_JWKS_BYTES:
                            raise JwksError("JWKS document too large")
                        chunks.append(chunk)
                    data = b"".join(chunks)
            finally:
                if self._http is None:
                    await client.aclose()
        if len(data) > MAX_JWKS_BYTES:
            raise JwksError("JWKS document too large")
        return data

    @staticmethod
    def _parse(data: bytes) -> dict[str, PyJWK]:
        try:
            document = json.loads(data)
        except ValueError as exc:
            raise JwksError("JWKS is not JSON") from exc
        entries = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise JwksError("JWKS has no keys list")
        keys: dict[str, PyJWK] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid or entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig":
                continue
            try:
                keys[kid] = PyJWK.from_dict(entry, algorithm="RS256")
            except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                continue
        if not keys:
            raise JwksError("JWKS contains no usable RS256 signing key")
        return keys

    async def _refresh(self) -> None:
        self._attempted_at = self._clock()
        try:
            async with asyncio.timeout(self._source.fetch_deadline_seconds):
                data = await self._load()
            keys = self._parse(data)
        except (httpx.HTTPError, OSError, JwksError, TimeoutError):
            return  # keep the previous keys; staleness limits how long they stay usable
        self._keys = keys
        self._fetched_at = self._clock()

    def _may_attempt(self, now: float) -> bool:
        return self._attempted_at is None or now - self._attempted_at >= MIN_REFETCH_SECONDS

    async def get(self, kid: str) -> PyJWK:
        now = self._clock()
        if kid in self._keys and self._age(now) < self._source.cache_seconds:
            return self._keys[kid]
        usable = self._age(now) < self._source.max_stale_seconds
        if self._lock.locked() and self._keys and kid not in self._keys:
            # A refresh is already in flight and we hold keys: an unknown kid is most
            # likely garbage, so fail fast instead of queueing behind the fetch. Key
            # rotation publishes new keys a cache period before using them (ADR-0001).
            raise InvalidTokenError("unknown signing key")
        if not (self._lock.locked() and kid in self._keys and usable):
            async with self._lock:
                now = self._clock()
                fresh = kid in self._keys and self._age(now) < self._source.cache_seconds
                if not fresh and self._may_attempt(now):
                    await self._refresh()
        if self._age(self._clock()) >= self._source.max_stale_seconds:
            raise InvalidTokenError("signing keys unavailable")
        key = self._keys.get(kid)
        if key is None:
            raise InvalidTokenError("unknown signing key")
        return key


class TokenVerifier:
    def __init__(self, policy: TokenPolicy, keys: JwksKeyStore) -> None:
        self._policy = policy
        self._keys = keys

    async def verify(self, token: str) -> VerifiedToken:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            raise InvalidTokenError("malformed token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("malformed token") from exc
        if header.get("alg") not in ALGORITHMS:
            raise InvalidTokenError("unsupported algorithm")
        if str(header.get("typ", "")).lower() not in ACCESS_TOKEN_TYPES:
            raise InvalidTokenError("not an access token")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidTokenError("missing key id")
        key = await self._keys.get(kid)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=ALGORITHMS,
                audience=self._policy.audience,
                issuer=self._policy.issuer,
                leeway=self._policy.leeway_seconds,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(type(exc).__name__) from exc
        now = time.time()
        leeway = self._policy.leeway_seconds
        issued_at, expires_at = claims["iat"], claims["exp"]
        if not isinstance(issued_at, int | float) or not isinstance(expires_at, int | float):
            raise InvalidTokenError("malformed timestamps")
        if issued_at > now + leeway:
            raise InvalidTokenError("issued in the future")
        if expires_at - issued_at > self._policy.max_lifetime_seconds + leeway:
            raise InvalidTokenError("lifetime exceeds access-token maximum")
        try:
            user_id = UUID(str(claims["sub"]))
        except ValueError as exc:
            raise InvalidTokenError("subject is not a user id") from exc
        return VerifiedToken(user_id=user_id, expires_at=int(claims["exp"]))
