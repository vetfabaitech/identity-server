"""Adapter settings, read from `VETFAB_AUTH_*` environment variables (or passed in directly).

Nothing environment-specific is hardcoded: the identity service's address comes from `VETFAB_AUTH_URL`, so the same
build runs against `http://localhost:8200` while developing and the deployed host later. Everything is validated at
construction and every problem is reported at once, naming the variable to fix.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

Environment = Literal["development", "test", "staging", "production"]
ENVIRONMENTS: tuple[Environment, ...] = ("development", "test", "staging", "production")

# CONTRACT.md: one audience for the whole platform, and the identity routes live under /auth.
DEFAULT_AUDIENCE = "vetfab"
AUTH_PATH = "/auth"
JWKS_PATH = "/auth/.well-known/jwks.json"
# CONTRACT.md: an access token is valid for at most 15 minutes.
MAX_TOKEN_LIFETIME_SECONDS = 900


class ConfigError(ValueError):
    """The adapter configuration is missing or unsafe. The message lists every problem found."""


def _origin_problem(name: str, value: str, *, require_https: bool) -> str | None:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return f"{name} must be an http(s) URL such as http://localhost:8200 (got {value!r})."
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        return f"{name} must be the service's origin only, without a path, query or credentials (got {value!r})."
    if require_https and parts.scheme != "https":
        return f"{name} must use https outside development and test."
    return None


@dataclass(frozen=True, slots=True)
class AdapterConfig:
    """`auth_url` is the identity service's origin; the rest derive from it unless overridden."""

    auth_url: str
    issuer: str
    audience: str
    jwks_url: str
    environment: Environment
    # Names this service in logs and docs. The identity service does not register clients today (the audience is
    # shared), so this is a label, never a credential.
    client_id: str = ""
    leeway_seconds: int = 30
    max_lifetime_seconds: int = MAX_TOKEN_LIFETIME_SECONDS

    @classmethod
    def build(
        cls,
        *,
        auth_url: str,
        environment: str,
        issuer: str | None = None,
        audience: str | None = None,
        jwks_url: str | None = None,
        client_id: str = "",
    ) -> "AdapterConfig":
        problems: list[str] = []
        auth_url = auth_url.strip().rstrip("/")
        if environment not in ENVIRONMENTS:
            problems.append(f"VETFAB_ENVIRONMENT must be one of {', '.join(ENVIRONMENTS)} (got {environment!r}).")
        secure = environment in ("staging", "production")
        if not auth_url:
            problems.append("VETFAB_AUTH_URL is required: the identity service's origin, e.g. http://localhost:8200.")
        else:
            problem = _origin_problem("VETFAB_AUTH_URL", auth_url, require_https=secure)
            if problem:
                problems.append(problem)
        issuer = (issuer or f"{auth_url}{AUTH_PATH}").strip().rstrip("/")
        jwks_url = (jwks_url or f"{auth_url}{JWKS_PATH}").strip()
        audience = (audience or DEFAULT_AUDIENCE).strip()
        if not audience:
            problems.append("VETFAB_AUTH_AUDIENCE must not be empty.")
        if secure:
            if not issuer.startswith("https://"):
                problems.append("VETFAB_AUTH_ISSUER must use https outside development and test.")
            if not jwks_url.startswith("https://"):
                problems.append("VETFAB_AUTH_JWKS_URL must use https outside development and test.")
        elif not (jwks_url.startswith("http://") or jwks_url.startswith("https://")):
            problems.append("VETFAB_AUTH_JWKS_URL must be an http(s) URL.")
        if problems:
            raise ConfigError("Invalid Vetfab identity configuration:\n- " + "\n- ".join(problems))
        return cls(
            auth_url=auth_url,
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            environment=environment,  # pyright: ignore[reportArgumentType]  # validated above
            client_id=client_id.strip(),
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AdapterConfig":
        env = os.environ if env is None else env
        return cls.build(
            auth_url=env.get("VETFAB_AUTH_URL", ""),
            environment=env.get("VETFAB_ENVIRONMENT", ""),
            issuer=env.get("VETFAB_AUTH_ISSUER") or None,
            audience=env.get("VETFAB_AUTH_AUDIENCE") or None,
            jwks_url=env.get("VETFAB_AUTH_JWKS_URL") or None,
            client_id=env.get("VETFAB_CLIENT_ID", ""),
        )
