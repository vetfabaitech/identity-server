"""Settings fail closed: test accounts never in production, https outside development, bounded token lifetime."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from identity.config import Settings

BASE: dict[str, Any] = {
    "environment": "staging",
    "database_url": "postgresql://lms_identity:x@db:5432/lms",
    "issuer": "https://test.vetfab.ai/auth",
    "audience": "vetfab-lms",
    "app_origins": "https://test.vetfab.ai",
    "keys_dir": "/keys",
}


def make(**overrides: Any) -> Settings:
    values = {**BASE, **overrides}
    return Settings(_env_file=None, **values)  # pyright: ignore[reportCallIssue]


def test_valid_staging_settings() -> None:
    settings = make()
    assert settings.deployed
    assert settings.secure_cookies
    assert settings.keys_dir == Path("/keys")
    assert settings.access_token_seconds == 900


@pytest.mark.parametrize("missing", ["environment", "database_url", "issuer", "audience", "app_origins", "keys_dir"])
def test_required_values_have_no_default(missing: str) -> None:
    values = {k: v for k, v in BASE.items() if k != missing}
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)  # pyright: ignore[reportCallIssue]


def test_test_accounts_are_refused_in_production() -> None:
    with pytest.raises(ValidationError, match="production"):
        make(
            environment="production",
            test_accounts=True,
            test_accounts_passphrase="a long enough passphrase",
            test_accounts_emails="admin@dev.vetfab.local",
        )


def test_test_accounts_need_a_passphrase_and_emails() -> None:
    with pytest.raises(ValidationError, match="PASSPHRASE"):
        make(test_accounts=True, test_accounts_emails="admin@dev.vetfab.local")
    with pytest.raises(ValidationError, match="PASSPHRASE"):
        make(test_accounts=True, test_accounts_passphrase="short", test_accounts_emails="admin@dev.vetfab.local")
    with pytest.raises(ValidationError, match="EMAILS"):
        make(test_accounts=True, test_accounts_passphrase="a long enough passphrase")


def test_test_account_emails_are_normalised_in_order() -> None:
    settings = make(
        test_accounts=True,
        test_accounts_passphrase="a long enough passphrase",
        test_accounts_emails=" Admin@Dev.Vetfab.Local, learner@dev.vetfab.local ,,",
    )
    assert settings.test_account_emails == ["admin@dev.vetfab.local", "learner@dev.vetfab.local"]


@pytest.mark.parametrize("field", ["issuer", "app_origins"])
def test_deployed_environments_require_https(field: str) -> None:
    with pytest.raises(ValidationError, match="https"):
        make(**{field: "http://test.vetfab.ai"})


def test_development_allows_http_and_plain_cookies() -> None:
    settings = make(environment="development", issuer="http://localhost:8200/auth", app_origins="http://localhost:3100")
    assert not settings.deployed
    assert not settings.secure_cookies


def test_app_origin_is_reduced_to_scheme_host_port() -> None:
    assert make(app_origins="https://test.vetfab.ai/some/path").app_origin == "https://test.vetfab.ai"


def test_access_tokens_never_outlive_fifteen_minutes() -> None:
    with pytest.raises(ValidationError):
        make(access_token_seconds=901)


def test_app_origins_is_a_normalised_list() -> None:
    settings = make(app_origins=" https://test.vetfab.ai/ ,https://demo.vetfab.ai:443/x, https://test.vetfab.ai")
    assert settings.app_origin_list == ["https://test.vetfab.ai", "https://demo.vetfab.ai:443"]
    assert settings.app_origin == "https://test.vetfab.ai"


def test_app_origins_must_name_at_least_one_origin() -> None:
    with pytest.raises(ValidationError, match="IDENTITY_APP_ORIGINS"):
        make(app_origins=" , ")


def test_every_origin_must_be_https_when_deployed() -> None:
    with pytest.raises(ValidationError, match="IDENTITY_APP_ORIGINS"):
        make(app_origins="https://test.vetfab.ai,http://demo.vetfab.ai")


def test_oauth_redirect_uri_is_under_the_issuer() -> None:
    settings = make(issuer="https://test.vetfab.ai/auth")
    assert settings.oauth_redirect_uri("github") == "https://test.vetfab.ai/auth/oauth/github/callback"


def test_admin_emails_are_lowercased_and_unique() -> None:
    assert make(admin_emails="A@x.io, a@x.io ,b@x.io").admin_email_list == ["a@x.io", "b@x.io"]


def test_provider_secrets_are_secret() -> None:
    settings = make(github_client_id="id", github_client_secret="shh", google_client_id="gid", google_client_secret="g")
    assert "shh" not in repr(settings)
    assert settings.github_client_secret is not None
    assert settings.github_client_secret.get_secret_value() == "shh"
