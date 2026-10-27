"""Vetfab identity adapter (backend).

Core (no web framework): `AdapterConfig`, `IdentityAdapter`, `VerifiedIdentity`, `bearer_token`, the errors.
SSO hand-off (destination side): `HandoffConfig`, `HandoffRedeemer`, `SessionCookie`.
FastAPI: `vetfab_identity_adapter.fastapi.IdentityGuard`, `handoff_router` (needs the `fastapi` extra).
"""

from vetfab_identity_adapter.adapter import IdentityAdapter, VerifiedIdentity, bearer_token
from vetfab_identity_adapter.config import AdapterConfig, ConfigError
from vetfab_identity_adapter.handoff import (
    HandoffConfig,
    HandoffRedeemer,
    HandoffRejectedError,
    HandoffUnavailableError,
    Redemption,
    SessionCookie,
)
from vetfab_identity_adapter.verifier import InvalidTokenError, SigningKeysUnavailableError

__all__ = [
    "AdapterConfig",
    "ConfigError",
    "HandoffConfig",
    "HandoffRedeemer",
    "HandoffRejectedError",
    "HandoffUnavailableError",
    "Redemption",
    "SessionCookie",
    "IdentityAdapter",
    "InvalidTokenError",
    "SigningKeysUnavailableError",
    "VerifiedIdentity",
    "bearer_token",
]
