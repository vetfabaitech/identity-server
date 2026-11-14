"""Settings for the identity service (environment prefix `IDENTITY_`).

Like the platform API's settings, environment-identifying values and secrets have no defaults, and the validator
refuses combinations that would weaken sign-in outside development: test accounts in production, plain-http issuer or
app origin on a deployed host, an access token longer than the 15 minutes the API accepts (plan §28).
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from identity.services import Registry, RegistryError, is_service_id, parse_registry

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

    # True (the contract's behaviour): GET /auth/login with a live sign-in session hands a token straight back to the
    # service that sent the person (single sign-on). False: it always shows the sign-in page, so the person chooses
    # GitHub, Google (each with its own account picker) or a password for every service. Deploy sets False.
    silent_sign_in: bool = True

    # The trusted service registry (identity/services.py): which services may receive an SSO hand-off, and the hash of
    # the secret each uses to redeem tickets. Empty switches hand-off off.
    services: str = ""
    # How long a hand-off ticket may wait to be redeemed. A ticket is single-use and bound to one destination.
    handoff_ticket_seconds: int = Field(default=60, ge=10, le=300)
    # How stale this instance's copy of the managed registry (and the sign-in origin allowlist built from it) may get.
    # Handoff issue, redemption and the service list always read the database; only origin checks use the copy, so a
    # change made on another instance reaches them within this many seconds (docs/developer-portal.md).
    registry_refresh_seconds: float = Field(default=5.0, ge=0, le=60)
    # After a service secret is rotated the previous one keeps working this long (0: revoked at once), so a service can
    # deploy the new one without dropping handoffs. A rotation can also revoke the old one immediately.
    secret_rotation_grace_seconds: int = Field(default=3600, ge=0, le=86_400)
    # Mutations per administrator per rate-limit window on the developer portal API; secret operations get a sixth.
    admin_rate_limit: int = Field(default=60, ge=6, le=1000)

    # The signed user feed (CONTRACT.md, "User feed"; identity/web/service_routes.py): comma-separated ids of registry
    # services that may read it, each authenticating with its registry secret and active. Empty switches the feed off.
    user_feed_services: str = ""
    # Feed requests per service in each 600-second window, before 429 with Retry-After (contract: 1200).
    user_feed_rate_limit: int = Field(default=1200, ge=10, le=100_000)
    # How long user events are kept before they may be purged. A consumer that falls further behind reconciles from
    # the user list. At least 7 days, so a product down over a long weekend does not have to reconcile.
    user_events_retention_days: int = Field(default=30, ge=7, le=3650)

    # Account status changes by a product (CONTRACT.md, "Account status"; POST /auth/service/users/{id}/status):
    # comma-separated ids of registry services whose backends may approve, reject or suspend an account on behalf of
    # one of their administrators. A separate permission from the feed: reading users never implies changing them.
    # Empty (the default) switches it off.
    account_status_services: str = ""
    # Status-change requests per service in each 600-second window, before 429 with Retry-After.
    account_status_rate_limit: int = Field(default=120, ge=1, le=10_000)

    # Developing against this deployed service from localhost (like a GitHub OAuth app's http://localhost callback). Off by
    # default. When on, an administrator may activate a `local` service whose base_url is exactly
    # http://localhost:<port> or http://127.0.0.1:<port>; it receives sign-ins (GET /auth/login) and nothing else: no
    # CORS, no switcher, no hand-off tickets. Refused in production.
    allow_localhost_dev_origins: bool = False

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

    @field_validator("user_feed_services", "account_status_services")
    @classmethod
    def _service_ids(cls, value: str, info: ValidationInfo) -> str:
        ids: list[str] = []
        for raw in value.split(","):
            service_id = raw.strip()
            if not service_id:
                continue
            if not is_service_id(service_id):
                name = f"IDENTITY_{(info.field_name or '').upper()}"
                raise ValueError(f"{name} must list service ids (got {service_id!r}).")
            if service_id not in ids:
                ids.append(service_id)
        return ",".join(ids)

    @model_validator(mode="after")
    def _fail_closed(self) -> "Settings":
        if self.deployed:
            if not self.issuer.startswith("https://"):
                raise ValueError("IDENTITY_ISSUER must use https outside development/test.")
            if any(not origin.startswith("https://") for origin in self.app_origin_list):
                raise ValueError("IDENTITY_APP_ORIGINS must use https outside development/test.")
        try:
            parse_registry(self.services, app_origins=self.app_origin_list, deployed=self.deployed)
        except RegistryError as exc:
            raise ValueError(f"IDENTITY_SERVICES: {exc}") from exc
        if self.allow_localhost_dev_origins and self.environment == "production":
            raise ValueError("IDENTITY_ALLOW_LOCALHOST_DEV_ORIGINS is refused in production.")
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
    def registry(self) -> Registry:
        return parse_registry(self.services, app_origins=self.app_origin_list, deployed=self.deployed)

    @property
    def app_origin_list(self) -> list[str]:
        return self.app_origins.split(",")

    @property
    def user_feed_service_ids(self) -> frozenset[str]:
        return frozenset(s for s in self.user_feed_services.split(",") if s)

    @property
    def account_status_service_ids(self) -> frozenset[str]:
        return frozenset(s for s in self.account_status_services.split(",") if s)

    @property
    def cors_origin_list(self) -> list[str]:
        """The app origins whose pages may call the credentialed endpoints (renewal, switcher, hand-off tickets).

        On a deployed service a plain-http origin can only be a localhost development origin (every other one must be
        https). It receives sign-ins through the redirect but never a readable cross-origin answer: its page is on a
        different site from the refresh cookie, so it cannot renew silently anyway.
        """
        return [o for o in self.app_origin_list if not (self.deployed and o.startswith("http://"))]

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
