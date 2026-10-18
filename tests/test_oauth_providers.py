"""GitHub and Google adapters against recorded API shapes (httpx MockTransport; no network)."""

from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from identity.config import Settings
from identity.oauth import PROVIDERS, OAuthError, Profile, configured_providers


def settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "staging",
        "database_url": "postgresql://x@db/lms",
        "issuer": "https://test.vetfab.ai/auth",
        "audience": "vetfab",
        "app_origins": "https://test.vetfab.ai",
        "keys_dir": Path("/keys"),
        "github_client_id": "gh-id",
        "github_client_secret": "gh-secret",
        "google_client_id": "g-id",
        "google_client_secret": "g-secret",
        **overrides,
    }
    return Settings(_env_file=None, **values)  # pyright: ignore[reportCallIssue]


def client(routes: dict[str, Any], seen: list[httpx.Request] | None = None) -> httpx.AsyncClient:
    def handle(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        reply = routes.get(f"{request.method} {request.url.copy_with(query=None)}")
        if reply is None:
            return httpx.Response(404)
        status, body = reply
        return httpx.Response(status, json=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handle))


GH_TOKEN = "POST https://github.com/login/oauth/access_token"
GH_USER = "GET https://api.github.com/user"
GH_EMAILS = "GET https://api.github.com/user/emails"
G_TOKEN = "POST https://oauth2.googleapis.com/token"
G_USER = "GET https://www.googleapis.com/oauth2/v3/userinfo"


def test_github_authorize_url_carries_client_callback_scope_and_state() -> None:
    url = PROVIDERS["github"].authorize_url(settings(), "nonce-1")
    parts = urlsplit(url)
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://github.com/login/oauth/authorize"
    assert query["client_id"] == "gh-id"
    assert query["redirect_uri"] == "https://test.vetfab.ai/auth/oauth/github/callback"
    assert query["scope"] == "read:user user:email"
    assert query["state"] == "nonce-1"


def test_google_authorize_url_asks_for_openid_email_profile() -> None:
    query = {k: v[0] for k, v in parse_qs(urlsplit(PROVIDERS["google"].authorize_url(settings(), "n")).query).items()}
    assert query["client_id"] == "g-id"
    assert query["redirect_uri"] == "https://test.vetfab.ai/auth/oauth/google/callback"
    assert query["response_type"] == "code"
    assert query["scope"] == "openid email profile"
    assert query["state"] == "n"


async def test_github_exchanges_the_code_with_the_registered_callback() -> None:
    seen: list[httpx.Request] = []
    routes = {
        GH_TOKEN: (200, {"access_token": "t"}),
        GH_USER: (200, {"id": 7, "login": "octo", "name": None, "email": None}),
        GH_EMAILS: (200, [{"email": "octo@x.io", "primary": True, "verified": True}]),
    }
    async with client(routes, seen) as c:
        await PROVIDERS["github"].fetch_profile(settings(), "code-1", c)
    form = {k: v[0] for k, v in parse_qs(seen[0].content.decode()).items()}
    assert form == {
        "client_id": "gh-id",
        "client_secret": "gh-secret",
        "code": "code-1",
        "redirect_uri": "https://test.vetfab.ai/auth/oauth/github/callback",
    }
    assert seen[1].headers["authorization"] == "Bearer t"


async def test_github_uses_verified_primary_email_when_profile_email_is_private() -> None:
    routes = {
        GH_TOKEN: (200, {"access_token": "t"}),
        GH_USER: (200, {"id": 7, "login": "octo", "name": None, "email": None}),
        GH_EMAILS: (
            200,
            [
                {"email": "old@x.io", "primary": False, "verified": True},
                {"email": "Octo@X.io", "primary": True, "verified": True},
            ],
        ),
    }
    async with client(routes) as c:
        profile = await PROVIDERS["github"].fetch_profile(settings(), "code", c)
    assert profile == Profile(
        provider="github", provider_user_id="7", email="Octo@X.io", email_verified=True, display_name="octo"
    )


async def test_github_public_email_counts_only_when_verified() -> None:
    routes = {
        GH_TOKEN: (200, {"access_token": "t"}),
        GH_USER: (200, {"id": 7, "login": "octo", "name": "Octo Cat", "email": "public@x.io"}),
        GH_EMAILS: (
            200,
            [
                {"email": "public@x.io", "primary": False, "verified": True},
                {"email": "primary@x.io", "primary": True, "verified": True},
            ],
        ),
    }
    async with client(routes) as c:
        profile = await PROVIDERS["github"].fetch_profile(settings(), "code", c)
    assert (profile.email, profile.email_verified, profile.display_name) == ("public@x.io", True, "Octo Cat")


async def test_github_unverified_email_is_reported_unverified() -> None:
    routes = {
        GH_TOKEN: (200, {"access_token": "t"}),
        GH_USER: (200, {"id": 7, "login": "octo", "email": "claimed@x.io"}),
        GH_EMAILS: (200, [{"email": "claimed@x.io", "primary": True, "verified": False}]),
    }
    async with client(routes) as c:
        profile = await PROVIDERS["github"].fetch_profile(settings(), "code", c)
    assert profile.email_verified is False


async def test_google_profile_maps_sub_and_email_verified() -> None:
    routes = {
        G_TOKEN: (200, {"access_token": "t", "token_type": "Bearer"}),
        G_USER: (200, {"sub": "1098", "email": "ada@gmail.com", "email_verified": True, "name": "Ada L"}),
    }
    async with client(routes) as c:
        profile = await PROVIDERS["google"].fetch_profile(settings(), "code", c)
    assert profile == Profile(
        provider="google", provider_user_id="1098", email="ada@gmail.com", email_verified=True, display_name="Ada L"
    )


async def test_google_without_a_name_uses_the_email_local_part() -> None:
    routes = {
        G_TOKEN: (200, {"access_token": "t"}),
        G_USER: (200, {"sub": "1", "email": "grace@x.io", "email_verified": False}),
    }
    async with client(routes) as c:
        profile = await PROVIDERS["google"].fetch_profile(settings(), "code", c)
    assert (profile.display_name, profile.email_verified) == ("grace", False)


@pytest.mark.parametrize(
    ("provider", "routes"),
    [
        ("github", {GH_TOKEN: (200, {"error": "bad_verification_code"})}),
        ("github", {GH_TOKEN: (500, {})}),
        ("github", {GH_TOKEN: (200, {"access_token": "t"}), GH_USER: (401, {})}),
        ("google", {G_TOKEN: (400, {"error": "invalid_grant"})}),
        ("google", {G_TOKEN: (200, {"access_token": "t"}), G_USER: (200, {"email": "no-sub@x.io"})}),
    ],
)
async def test_provider_failures_raise_oauth_error(provider: str, routes: dict[str, Any]) -> None:
    async with client(routes) as c:
        with pytest.raises(OAuthError) as caught:
            await PROVIDERS[provider].fetch_profile(settings(), "code", c)
    assert caught.value.reason == "provider"


async def test_a_network_failure_is_an_oauth_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as c:
        with pytest.raises(OAuthError):
            await PROVIDERS["github"].fetch_profile(settings(), "code", c)


def test_configured_providers_requires_id_and_secret() -> None:
    assert configured_providers(settings()) == ["github", "google"]
    assert configured_providers(settings(google_client_secret=None)) == ["github"]
    assert configured_providers(settings(github_client_id="", google_client_id="")) == []


def test_secrets_never_appear_in_the_authorize_url() -> None:
    for name in ("github", "google"):
        assert "secret" not in PROVIDERS[name].authorize_url(settings(), "n")


async def test_the_provider_error_code_is_kept_for_the_log() -> None:
    async with client({GH_TOKEN: (200, {"error": "redirect_uri_mismatch", "error_description": "bad"})}) as c:
        with pytest.raises(OAuthError) as caught:
            await PROVIDERS["github"].fetch_profile(settings(), "code", c)
    assert "redirect_uri_mismatch" in str(caught.value)
    assert "gh-secret" not in str(caught.value)
