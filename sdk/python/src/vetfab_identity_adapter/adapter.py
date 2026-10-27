"""The framework-neutral core: configuration in, verified identity out."""

import time
from collections.abc import Callable

import httpx

from vetfab_identity_adapter.config import AdapterConfig
from vetfab_identity_adapter.verifier import (
    InvalidTokenError,
    JwksKeyStore,
    JwksSource,
    SigningKeysUnavailableError,
    TokenPolicy,
    TokenVerifier,
    VerifiedToken,
)

# What application code receives: the one thing the token proves. Email, name, status and roles are the product's own
# data about this id (CONTRACT.md: "products must not trust anything but `sub`").
VerifiedIdentity = VerifiedToken

__all__ = [
    "IdentityAdapter",
    "InvalidTokenError",
    "SigningKeysUnavailableError",
    "VerifiedIdentity",
    "bearer_token",
]


def bearer_token(authorization: str | None) -> str | None:
    """The token in an `Authorization: Bearer <token>` header, or None when absent or not exactly that shape."""
    if not authorization:
        return None
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    return parts[1]


class IdentityAdapter:
    """Verifies the identity service's access tokens against its published keys.

    One instance per process: it caches the signing keys (about 5 minutes, refetching at most every 30 seconds for an
    unknown `kid`, no longer trusting them an hour after the last successful fetch; CONTRACT.md "Keys").
    """

    def __init__(
        self,
        config: AdapterConfig,
        *,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self._http = http
        self._verifier = TokenVerifier(
            TokenPolicy(
                issuer=config.issuer,
                audience=config.audience,
                leeway_seconds=config.leeway_seconds,
                max_lifetime_seconds=config.max_lifetime_seconds,
            ),
            JwksKeyStore(JwksSource(url=config.jwks_url), http=http, clock=clock),
        )

    @classmethod
    def from_env(cls) -> "IdentityAdapter":
        return cls(AdapterConfig.from_env())

    async def verify(self, token: str) -> VerifiedIdentity:
        """The verified identity in `token`. Raises InvalidTokenError (401), or SigningKeysUnavailableError (503)."""
        return await self._verifier.verify(token)

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
