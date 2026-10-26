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
    # (README.md, "Database"). Never the schema owner on a deployed host.
    database_url: str = Field(min_length=1)

    # `iss` stamped on access tokens, e.g. https://test.vetfab.ai/auth. The API's LMS_TOKEN_ISSUER must match.
    issuer: str = Field(min_length=1)
    # `aud` stamped on access tokens. The API's LMS_TOKEN_AUDIENCE must match.
    audience: str = Field(min_length=1)
    # Comma-separated origins (scheme + host + port) whose /handoff may receive a token (spec SI-3, SI-4). The first
    # is the default: a path-only `redirect` lands there. The LMS web app comes first; the IDE follows.
    app_origins: str = Field(min_length=1)

    # Directory of RSA private keys, one `<kid>.pem` each; the newest signs, all are published (keys.py).
    keys_dir: Path

    # Access-token lifetime. Every product rejects anything longer than 900 s (CONTRACT.md).
    access_token_seconds: int = Field(default=900, ge=60, le=900)
    # Refresh session lifetime. Each use rotates the token; this bounds a session left alone.
    refresh_token_days: int = Field(default=30, ge=1, le=90)
    # A refresh token rotated this recently may still mint an access token (two tabs renewing at once),
    # without issuing another refresh token. Older reuse revokes the whole session.
    refresh_grace_seconds: int = Field(default=30, ge=0, le=120)

    # Failed sign-ins allowed in one window, three independent counters (load test 2026-10-26, finding 1):
    # per account *and* client address (one person mistyping; the common case, and the one a stranger on another
    # address cannot trip), per account from anywhere (caps the hashing one account can cost, and a slow lockout
    # from a single address), and per client address across accounts (a password spray from one place). The address
    # limit is high because a college sits behind one public address: 1,000 students at 3 sign-ins/s with 10 % of
    # them mistyping once is 180 failures in 10 minutes; 500 keeps that clear while a spray of 500 guesses in
    # 10 minutes, one per account, is still refused.
    rate_limit_attempts: int = Field(default=10, ge=3, le=100)
    rate_limit_account_attempts: int = Field(default=50, ge=3, le=1000)
    rate_limit_address_attempts: int = Field(default=500, ge=10, le=100_000)
    rate_limit_window_seconds: int = Field(default=600, ge=60, le=86_400)

    # Password checks running at once per process, and how long a sign-in waits for one before answering
    # 503 busy (perf design 2026-10-24 §10). Each argon2id check takes 64 MiB (passwords.py), so 2 fits the
    # 256 MiB container; unbounded checks were OOM-killed by 60 simultaneous sign-ins.
    max_concurrent_verifies: int = Field(default=2, ge=1, le=64)
    verify_queue_seconds: float = Field(default=3.0, ge=0.5, le=30)
    # How long a request waits for a pooled database connection before it is answered 503 busy (web/app.py).
    # Sign-ins never contend for the pool (routes.login takes a verify slot first), so this is reached only by a
    # storm of renewals, which are cheap and best served late rather than refused: a product treats a refused
    # renewal as a sign-out. Load test 2026-10-26: 1,000 renewals at once drain in ~22 s on one core.
    db_wait_seconds: float = Field(default=30.0, ge=0.5, le=120)

    # Test-accounts mode (spec TD-9): a passphrase-gated page that signs in as one of the listed accounts.
    # Refused in production.
    test_accounts: bool = False
    test_accounts_passphrase: SecretStr | None = None
    # Comma-separated emails the picker offers, in display order.
    test_accounts_emails: str = ""
    # Password `identity-admin seed-test-accounts` sets on those accounts.
    test_accounts_password: SecretStr | None = None

    # OAuth clients (spec SI-5). A provider is offered only when both its id and secret are set. The callback each
    # must register is `oauth_redirect_uri(provider)`.
    github_client_id: str = ""
    github_client_secret: SecretStr | None = None
    google_client_id: str = ""
    google_client_secret: SecretStr | None = None

    # Comma-separated emails that become approved administrators on OAuth sign-in (the IDE's BETA_ADMIN_EMAILS
    # bootstrap, spec SI-5/SI-7).
    admin_emails: str = ""

    @field_validator("app_origins")
    @classmethod
    def _origins_only(cls, value: str) -> str:
        origins: list[str] = []
        for raw in value.split(","):
            if not raw.strip():
                continue
            parts = urlsplit(raw.strip())
            if parts.scheme not in ("http", "https") or not parts.netloc:
                raise ValueError("IDENTITY_APP_ORIGINS must list http(s) origins.")
            # A browser's Origin header never carries the scheme's default port, so neither may an entry.
            default_port = {"http": 80, "https": 443}[parts.scheme]
            host = parts.hostname or ""
            port = f":{parts.port}" if parts.port and parts.port != default_port else ""
            origin = f"{parts.scheme}://{host}{port}"
            if origin not in origins:
                origins.append(origin)
        if not origins:
            raise ValueError("IDENTITY_APP_ORIGINS must list at least one origin.")
        return ",".join(origins)

    @model_validator(mode="after")
    def _fail_closed(self) -> "Settings":
        if self.deployed:
            if not self.issuer.startswith("https://"):
                raise ValueError("IDENTITY_ISSUER must use https outside development/test.")
            if any(not origin.startswith("https://") for origin in self.app_origin_list):
                raise ValueError("IDENTITY_APP_ORIGINS must use https outside development/test.")
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
    def app_origin_list(self) -> list[str]:
        return self.app_origins.split(",")

    @property
    def app_origin(self) -> str:
        """The default hand-off origin: the first of IDENTITY_APP_ORIGINS."""
        return self.app_origin_list[0]

    @property
    def admin_email_list(self) -> list[str]:
        return _email_list(self.admin_emails)

    def oauth_redirect_uri(self, provider: str) -> str:
        """The provider callback: always the mounted route /auth/oauth/<provider>/callback on the issuer's origin, so a
        go-live issuer without the /auth suffix (https://auth.vetfab.ai) still registers the right URL."""
        parts = urlsplit(self.issuer)
        return f"{parts.scheme}://{parts.netloc}/auth/oauth/{provider}/callback"

    @property
    def deployed(self) -> bool:
        return self.environment in ("staging", "production")

    @property
    def secure_cookies(self) -> bool:
        """Secure, `__Secure-`-prefixed cookies whenever the app is served over https."""
        return self.app_origin.startswith("https://")

    @property
    def test_account_emails(self) -> list[str]:
        return _email_list(self.test_accounts_emails)


def _email_list(value: str) -> list[str]:
    seen: list[str] = []
    for raw in value.split(","):
        email = raw.strip().lower()
        if email and email not in seen:
            seen.append(email)
    return seen


@lru_cache
def get_settings() -> Settings:
    return Settings()  # pyright: ignore[reportCallIssue]  # values come from the environment
