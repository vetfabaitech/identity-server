import pytest

from vetfab_identity_adapter import AdapterConfig, ConfigError


def test_derives_everything_from_the_auth_url() -> None:
    config = AdapterConfig.from_env({"VETFAB_AUTH_URL": "http://localhost:8200/", "VETFAB_ENVIRONMENT": "development"})
    assert config.auth_url == "http://localhost:8200"
    assert config.issuer == "http://localhost:8200/auth"
    assert config.jwks_url == "http://localhost:8200/auth/.well-known/jwks.json"
    assert config.audience == "vetfab"


def test_overrides_are_honoured() -> None:
    config = AdapterConfig.from_env(
        {
            "VETFAB_AUTH_URL": "https://id.example",
            "VETFAB_ENVIRONMENT": "production",
            "VETFAB_AUTH_ISSUER": "https://id.example/auth",
            "VETFAB_AUTH_AUDIENCE": "other",
            "VETFAB_AUTH_JWKS_URL": "https://keys.example/jwks.json",
            "VETFAB_CLIENT_ID": "vetfab-lms",
        }
    )
    assert (config.audience, config.jwks_url, config.client_id) == (
        "other",
        "https://keys.example/jwks.json",
        "vetfab-lms",
    )


def test_missing_values_are_all_reported_at_once() -> None:
    with pytest.raises(ConfigError) as caught:
        AdapterConfig.from_env({})
    message = str(caught.value)
    assert "VETFAB_AUTH_URL is required" in message
    assert "VETFAB_ENVIRONMENT must be one of" in message


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_plain_http_is_refused_when_deployed(environment: str) -> None:
    with pytest.raises(ConfigError, match="must use https"):
        AdapterConfig.from_env({"VETFAB_AUTH_URL": "http://auth.example", "VETFAB_ENVIRONMENT": environment})


def test_plain_http_jwks_is_refused_when_deployed() -> None:
    with pytest.raises(ConfigError, match="VETFAB_AUTH_JWKS_URL must use https"):
        AdapterConfig.from_env(
            {
                "VETFAB_AUTH_URL": "https://auth.example",
                "VETFAB_ENVIRONMENT": "production",
                "VETFAB_AUTH_JWKS_URL": "http://auth.example/jwks",
            }
        )


@pytest.mark.parametrize(
    "url", ["localhost:8200", "http://localhost:8200/auth", "http://user@localhost:8200", "ftp://x"]
)
def test_auth_url_must_be_an_origin(url: str) -> None:
    with pytest.raises(ConfigError, match="VETFAB_AUTH_URL"):
        AdapterConfig.from_env({"VETFAB_AUTH_URL": url, "VETFAB_ENVIRONMENT": "development"})
