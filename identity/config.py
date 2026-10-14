"""Settings for the identity service (environment prefix `IDENTITY_`).

Like the platform API's settings, environment-identifying values and secrets have no defaults, and the validator
refuses combinations that would weaken sign-in outside development: test accounts in production, plain-http issuer or
app origin on a deployed host, an access token longer than the 15 minutes the API accepts (plan §28).
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_PASSPHRASE_LENGTH = 12


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDENTITY_", env_file=".env", extra="ignore")

    # Deployment environment. Required: a missing value must not enable development behaviour.
    environment: Literal["development", "test", "staging", "production"]

    # psycopg URL for the service login: a member of `identity_app` and nothing else
    # (docs/operations/runbooks/database-roles.md). Never the schema owner on a deployed host.
    database_url: str = Field(min_length=1)

    # `iss` stamped on access tokens, e.g. https://test.vetfab.ai/auth. The API's LMS_TOKEN_ISSUER must match.
    issuer: str = Field(min_length=1)
    # `aud` stamped on access tokens. The API's LMS_TOKEN_AUDIENCE must match.
    audience: str = Field(min_length=1)
    # Origin of the LMS web app, whose /handoff receives the token (scheme + host + port).
    app_origin: str = Field(min_length=1)

    # Directory of RSA private keys, one `<kid>.pem` each; the newest signs, all are published (keys.py).
    keys_dir: Path

    # Access-token lifetime. The API rejects anything longer than 900 s (packages/authz TokenPolicy).
    access_token_seconds: int = Field(default=900, ge=60, le=900)
    # Refresh session lifetime. Each use rotates the token; this bounds a session left alone.
    refresh_token_days: int = Field(default=30, ge=1, le=90)
    # A refresh token rotated this recently may still mint an access token (two tabs renewing at once),
    # without issuing another refresh token. Older reuse revokes the whole session.
    refresh_grace_seconds: int = Field(default=30, ge=0, le=120)

    # Failed sign-ins allowed per email and per client address in one window.
    rate_limit_attempts: int = Field(default=10, ge=3, le=100)
    rate_limit_window_seconds: int = Field(default=600, ge=60, le=86_400)

    # Test-accounts mode (spec TD-9): a passphrase-gated page that signs in as one of the listed accounts.
    # Refused in production.
    test_accounts: bool = False
    test_accounts_passphrase: SecretStr | None = None
    # Comma-separated emails the picker offers, in display order.
    test_accounts_emails: str = ""
    # Password `identity-admin seed-test-accounts` sets on those accounts.
    test_accounts_password: SecretStr | None = None

    @field_validator("app_origin")
    @classmethod
    def _origin_only(cls, value: str) -> str:
        parts = urlsplit(value.strip())
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("IDENTITY_APP_ORIGIN must be an http(s) origin.")
        return f"{parts.scheme}://{parts.netloc}"

    @model_validator(mode="after")
    def _fail_closed(self) -> "Settings":
        if self.deployed:
            if not self.issuer.startswith("https://"):
                raise ValueError("IDENTITY_ISSUER must use https outside development/test.")
            if not self.app_origin.startswith("https://"):
                raise ValueError("IDENTITY_APP_ORIGIN must use https outside development/test.")
        if self.test_accounts:
            if self.environment == "production":
                raise ValueError("IDENTITY_TEST_ACCOUNTS is refused in production.")
            passphrase = self.test_accounts_passphrase.get_secret_value() if self.test_accounts_passphrase else ""
            if len(passphrase) < MIN_PASSPHRASE_LENGTH:
                raise ValueError(
                    f"IDENTITY_TEST_ACCOUNTS_PASSPHRASE of at least {MIN_PASSPHRASE_LENGTH} characters is required."
                )
            if not self.test_account_emails:
                raise ValueError("IDENTITY_TEST_ACCOUNTS_EMAILS must list at least one account.")
        return self

    @property
    def deployed(self) -> bool:
        return self.environment in ("staging", "production")

    @property
    def secure_cookies(self) -> bool:
        """Secure, `__Secure-`-prefixed cookies whenever the app is served over https."""
        return self.app_origin.startswith("https://")

    @property
    def test_account_emails(self) -> list[str]:
        seen: list[str] = []
        for raw in self.test_accounts_emails.split(","):
            email = raw.strip().lower()
            if email and email not in seen:
                seen.append(email)
        return seen


@lru_cache
def get_settings() -> Settings:
    return Settings()  # pyright: ignore[reportCallIssue]  # values come from the environment
