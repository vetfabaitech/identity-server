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
    "app_origin": "https://test.vetfab.ai",
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


@pytest.mark.parametrize("missing", ["environment", "database_url", "issuer", "audience", "app_origin", "keys_dir"])
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


@pytest.mark.parametrize("field", ["issuer", "app_origin"])
def test_deployed_environments_require_https(field: str) -> None:
    with pytest.raises(ValidationError, match="https"):
        make(**{field: "http://test.vetfab.ai"})


def test_development_allows_http_and_plain_cookies() -> None:
    settings = make(environment="development", issuer="http://localhost:8200/auth", app_origin="http://localhost:3100")
    assert not settings.deployed
    assert not settings.secure_cookies


def test_app_origin_is_reduced_to_scheme_host_port() -> None:
    assert make(app_origin="https://test.vetfab.ai/some/path").app_origin == "https://test.vetfab.ai"


def test_access_tokens_never_outlive_fifteen_minutes() -> None:
    with pytest.raises(ValidationError):
        make(access_token_seconds=901)
