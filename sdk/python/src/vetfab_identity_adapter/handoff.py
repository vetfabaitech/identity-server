"""The destination service's side of an SSO hand-off, with no web framework.

A ticket reaches the destination as a form POST from the source service's page. The destination's *backend*:

1. redeems it with the identity service, server to server, proving itself with this service's secret
   (`HandoffRedeemer`): the identity service answers with who the person is and never hands a token to the browser;
2. checks the browser really came from the source service the ticket was issued to (login-CSRF defence, below);
3. decides for itself whether that person may use this service (the application's own `load_user`);
4. starts this service's *own* session (`SessionCookie`): an HttpOnly cookie signed with a key only this service
   holds, valid for this service's origin only, which no other service can read or accept.

Login CSRF: without step 2, an attacker could sign in as themselves, obtain a ticket and send a victim to the
destination with it, signing the victim in as the attacker. A ticket is only accepted from a page on the source
service's origin (the browser sets `Origin` on a cross-site POST; a page the attacker controls cannot forge it).

Configuration (environment, validated at start-up):

    VETFAB_SERVICE_ID        this service's id in the identity service's registry
    VETFAB_SERVICE_SECRET    its redemption secret (server-side only; `identity-admin service-secret` makes one)
    VETFAB_SESSION_SECRET    at least 32 characters; signs this service's session cookie (never shared)
    VETFAB_APP_URL           this service's own origin, e.g. http://localhost:8301
    VETFAB_SESSION_SECONDS   optional, default 900, at most 3600
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from vetfab_identity_adapter.config import AdapterConfig, ConfigError
from vetfab_identity_adapter.verifier import VerifiedToken

log = logging.getLogger("vetfab_identity_adapter")

MIN_SECRET_LENGTH = 32
DEFAULT_SESSION_SECONDS = 900
MAX_SESSION_SECONDS = 3600
REDEEM_TIMEOUT_SECONDS = 5.0
REDEEM_PATH = "/auth/handoff/redeem"


@dataclass(frozen=True, slots=True)
class HandoffConfig:
    service_id: str
    service_secret: str = field(repr=False)
    session_secret: str = field(repr=False)
    app_url: str
    session_seconds: int = DEFAULT_SESSION_SECONDS

    @property
    def secure_cookies(self) -> bool:
        return self.app_url.startswith("https://")

    @classmethod
    def build(
        cls,
        adapter: AdapterConfig,
        *,
        service_id: str,
        service_secret: str,
        session_secret: str,
        app_url: str,
        session_seconds: int = DEFAULT_SESSION_SECONDS,
    ) -> "HandoffConfig":
        problems: list[str] = []
        if not service_id:
            problems.append("VETFAB_SERVICE_ID is required: this service's id in the identity registry.")
        if not service_secret:
            problems.append("VETFAB_SERVICE_SECRET is required (identity-admin service-secret makes one).")
        if len(session_secret) < MIN_SECRET_LENGTH:
            problems.append(f"VETFAB_SESSION_SECRET must be at least {MIN_SECRET_LENGTH} characters.")
        parts = urlsplit(app_url)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.path not in ("", "/") or parts.query:
            problems.append(
                f"VETFAB_APP_URL must be this service's origin, e.g. http://localhost:8301 (got {app_url!r})."
            )
        elif adapter.environment in ("staging", "production") and parts.scheme != "https":
            problems.append("VETFAB_APP_URL must use https outside development and test.")
        if not 60 <= session_seconds <= MAX_SESSION_SECONDS:
            problems.append(f"VETFAB_SESSION_SECONDS must be between 60 and {MAX_SESSION_SECONDS}.")
        if problems:
            raise ConfigError("Invalid Vetfab hand-off configuration:\n- " + "\n- ".join(problems))
        origin = f"{parts.scheme}://{parts.netloc}"
        return cls(service_id, service_secret, session_secret, origin, session_seconds)

    @classmethod
    def from_env(cls, adapter: AdapterConfig, env: Mapping[str, str]) -> "HandoffConfig":
        try:
            seconds = int(env.get("VETFAB_SESSION_SECONDS") or DEFAULT_SESSION_SECONDS)
        except ValueError:
            seconds = 0
        return cls.build(
            adapter,
            service_id=env.get("VETFAB_SERVICE_ID", ""),
            service_secret=env.get("VETFAB_SERVICE_SECRET", ""),
            session_secret=env.get("VETFAB_SESSION_SECRET", ""),
            app_url=env.get("VETFAB_APP_URL", ""),
            session_seconds=seconds,
        )


# --------------------------------------------------------------------------- redeeming


class HandoffRejectedError(Exception):
    """The ticket is not good: unknown, used, expired, for another service, or its session has ended. Maps to 400/403."""


class HandoffUnavailableError(Exception):
    """The identity service could not be asked, or refused this service's credentials. Maps to 503."""


@dataclass(frozen=True, slots=True)
class Redemption:
    user_id: UUID
    source_service: str
    source_origin: str
    # A path on this service, already screened by the identity service and screened again here.
    return_path: str


def _safe_local_path(value: object) -> str:
    if isinstance(value, str) and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        if not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value) and len(value) <= 2048:
            return value
    return "/"


class HandoffRedeemer:
    def __init__(self, adapter: AdapterConfig, config: HandoffConfig, *, http: httpx.AsyncClient | None = None) -> None:
        self._url = f"{adapter.auth_url}{REDEEM_PATH}"
        self._config = config
        self._http = http

    async def redeem(self, ticket: str) -> Redemption:
        if not ticket or len(ticket) > 256:
            raise HandoffRejectedError("malformed ticket")
        client = self._http or httpx.AsyncClient(timeout=REDEEM_TIMEOUT_SECONDS)
        try:
            response = await client.post(
                self._url,
                json={"ticket": ticket},
                auth=(self._config.service_id, self._config.service_secret),
                timeout=REDEEM_TIMEOUT_SECONDS,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            log.error("identity service unreachable for hand-off redemption: %s", type(exc).__name__)
            raise HandoffUnavailableError("identity service unreachable") from None
        finally:
            if self._http is None:
                await client.aclose()
        if response.status_code == 400:
            raise HandoffRejectedError("ticket refused")
        if response.status_code == 403:
            # The identity service recognised this service's credentials but the service is disabled or not approved.
            log.warning("hand-off refused: this service is not active in the identity registry")
            raise HandoffRejectedError("service not active")
        if response.status_code != 200:
            # 401 means the identity service refused THIS service's credentials: an operator problem, not the person's.
            log.error("hand-off redemption failed with HTTP %s (check VETFAB_SERVICE_ID/SECRET)", response.status_code)
            raise HandoffUnavailableError(f"identity service answered {response.status_code}")
        try:
            body = response.json()
            return Redemption(
                user_id=UUID(body["user_id"]),
                source_service=str(body["source_service"]),
                source_origin=str(body["source_origin"]),
                return_path=_safe_local_path(body.get("return_path")),
            )
        except (ValueError, KeyError, TypeError):
            raise HandoffUnavailableError("unexpected redemption answer") from None


# --------------------------------------------------------------------------- this service's own session


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SessionCookie:
    """A signed, expiring cookie that says "this browser is user X on THIS service".

    `<payload>.<HMAC-SHA256>` keyed by VETFAB_SESSION_SECRET and naming the service, so a cookie minted by one service
    (or by anyone without the key) is meaningless to every other. It carries no profile or role: those come from the
    application's own records on each request. It is a *local* session: signing out of the identity service does not
    reach it, so its lifetime is short (VETFAB_SESSION_SECONDS) and the application re-checks the account on every request.
    """

    def __init__(self, config: HandoffConfig) -> None:
        self._config = config
        self._key = config.session_secret.encode()
        prefix = "__Host-" if config.secure_cookies else ""
        # The service id is in the name: browsers do not isolate cookies by port, so two services on one host
        # (a local demo, or a shared staging host) must not overwrite each other's session.
        self.name = f"{prefix}vf_session_{config.service_id}"
        self.max_age = config.session_seconds

    def _sign(self, payload: str) -> str:
        return _b64(hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).digest())

    def issue(self, user_id: UUID, now: float | None = None) -> str:
        issued = int(time.time() if now is None else now)
        body = {"sub": str(user_id), "svc": self._config.service_id, "iat": issued, "exp": issued + self.max_age}
        payload = _b64(json.dumps(body, separators=(",", ":")).encode())
        return f"{payload}.{self._sign(payload)}"

    def read(self, value: str | None, now: float | None = None) -> VerifiedToken | None:
        if not value or len(value) > 1024 or value.count(".") != 1:
            return None
        payload, signature = value.split(".")
        if not hmac.compare_digest(signature, self._sign(payload)):
            return None
        try:
            body = json.loads(_unb64(payload))
            if body["svc"] != self._config.service_id:
                return None
            moment = time.time() if now is None else now
            if not isinstance(body["exp"], int) or body["exp"] <= moment or body["iat"] > moment + 30:
                return None
            return VerifiedToken(user_id=UUID(body["sub"]), expires_at=body["exp"])
        except (ValueError, KeyError, TypeError, binascii.Error):
            return None

    def cookie_attributes(self) -> dict[str, object]:
        return {
            "max_age": self.max_age,
            "path": "/",
            "secure": self._config.secure_cookies,
            "httponly": True,
            "samesite": "lax",
        }
