"""GitHub and Google sign-in over HTTP (spec SI-5, §4): start, provider round trip, callback, hand-off."""

from collections.abc import AsyncIterator, Callable
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from identity.config import Settings
from identity.oauth import PROVIDERS, OAuthError, Profile
from identity.store import User
from tests.conftest import ORIGIN, build_app, client_for, make_settings
from tests.test_http import verify

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

IDE = "https://demo.vetfab.ai"
REFRESH = "__Secure-vf_refresh"
OAUTH_STATE = "__Secure-vf_oauth_state"


@pytest.fixture
def oauth_settings(login_url: str, keys_dir: Path) -> Settings:
    return make_settings(
        login_url,
        keys_dir,
        app_origins=f"{ORIGIN},{IDE}",
        github_client_id="gh-id",
        github_client_secret="gh-secret",
    )


@pytest.fixture
async def client(
    oauth_settings: Settings, pool: AsyncConnectionPool, keys_dir: Path
) -> AsyncIterator[httpx.AsyncClient]:
    async with client_for(build_app(oauth_settings, pool, keys_dir)) as c:
        yield c


def fake_github(monkeypatch: pytest.MonkeyPatch, result: Profile | OAuthError) -> list[str]:
    codes: list[str] = []

    async def fetch_profile(settings: Settings, code: str, client: object = None) -> Profile:
        codes.append(code)
        if isinstance(result, OAuthError):
            raise result
        return result

    monkeypatch.setattr(PROVIDERS["github"], "fetch_profile", fetch_profile)
    return codes


def github_profile(email: str, *, pid: str = "gh-100", verified: bool = True) -> Profile:
    return Profile(provider="github", provider_user_id=pid, email=email, email_verified=verified, display_name="Octo")


async def start(client: httpx.AsyncClient, redirect: str = "/learn", state: str = "s1") -> str:
    """Runs the start step and returns the nonce GitHub would echo back as `state`."""
    response = await client.get("/auth/oauth/github/start", params={"redirect": redirect, "state": state})
    assert response.status_code == 302, response.text
    query = parse_qs(urlsplit(response.headers["location"]).query)
    return query["state"][0]


def fragment_of(response: httpx.Response) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).fragment).items()}


async def test_start_sets_state_cookie_and_redirects_to_provider(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/oauth/github/start", params={"redirect": "/learn", "state": "s1"})
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.netloc == "github.com"
    nonce = parse_qs(location.query)["state"][0]
    assert len(nonce) >= 40
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{OAUTH_STATE}=")
    for attribute in ("Path=/auth", "HttpOnly", "Secure", "SameSite=lax", "Max-Age=600"):
        assert attribute.lower() in cookie.lower()


async def test_start_404_when_provider_unconfigured(client: httpx.AsyncClient) -> None:
    assert (await client.get("/auth/oauth/google/start")).status_code == 404
    assert (await client.get("/auth/oauth/gitlab/start")).status_code == 404


async def test_callback_hands_off_new_user_as_pending(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, owner_url: str
) -> None:
    codes = fake_github(monkeypatch, github_profile("first-oauth@dev.vetfab.local"))
    nonce = await start(client)
    response = await client.get("/auth/oauth/github/callback", params={"code": "c-1", "state": nonce})
    assert response.status_code == 303, response.text
    assert response.headers["location"].startswith(f"{ORIGIN}/handoff#")
    fragment = fragment_of(response)
    assert (fragment["redirect"], fragment["state"]) == ("/learn", "s1")
    assert codes == ["c-1"]
    assert client.cookies.get(REFRESH)
    assert client.cookies.get(OAUTH_STATE) is None, "the state cookie is single-use"
    with psycopg.connect(owner_url) as conn:
        row = conn.execute(
            """SELECT u.status, (SELECT array_agg(action ORDER BY id) FROM identity.audit a WHERE a.user_id = u.id)
                 FROM public.users u WHERE email = 'first-oauth@dev.vetfab.local'"""
        ).fetchone()
    assert row is not None
    assert row[0] == "pending"
    assert row[1][-1] == "oauth_signin"


async def test_returning_user_signs_in_to_the_same_account(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    make_user: Callable[..., User],
    keys_dir: Path,
    tmp_path: Path,
) -> None:
    """Linked by verified email on the first pass, matched by provider id on the second."""
    user = make_user("returning@dev.vetfab.local")
    fake_github(monkeypatch, github_profile("returning@dev.vetfab.local", pid="gh-200"))
    subjects = []
    for _ in range(2):
        nonce = await start(client)
        response = await client.get("/auth/oauth/github/callback", params={"code": "c", "state": nonce})
        assert response.status_code == 303
        subjects.append(await verify(fragment_of(response)["token"], keys_dir, tmp_path))
    assert subjects == [str(user.id), str(user.id)]


async def test_callback_with_wrong_state_is_refused(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, owner_url: str
) -> None:
    codes = fake_github(monkeypatch, github_profile("csrf-victim@dev.vetfab.local"))
    await start(client)
    response = await client.get("/auth/oauth/github/callback", params={"code": "attacker", "state": "forged"})
    assert response.status_code == 400
    assert "expired" in response.text
    assert codes == [], "the code is never exchanged"
    assert client.cookies.get(REFRESH) is None
    with psycopg.connect(owner_url) as conn:
        assert (
            conn.execute("SELECT 1 FROM public.users WHERE email = 'csrf-victim@dev.vetfab.local'").fetchone() is None
        )


async def test_callback_without_the_state_cookie_is_refused(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    codes = fake_github(monkeypatch, github_profile("nocookie@dev.vetfab.local"))
    response = await client.get("/auth/oauth/github/callback", params={"code": "c", "state": "anything"})
    assert response.status_code == 400
    assert codes == []


async def test_provider_error_shows_a_message(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    codes = fake_github(monkeypatch, github_profile("x@dev.vetfab.local"))
    nonce = await start(client)
    response = await client.get("/auth/oauth/github/callback", params={"error": "access_denied", "state": nonce})
    assert response.status_code == 400
    assert "cancelled" in response.text
    assert 'name="password"' in response.text, "the sign-in page, so the user can try another way"
    assert codes == []


async def test_provider_failure_is_a_502_with_a_message(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_github(monkeypatch, OAuthError("provider", "token exchange failed"))
    nonce = await start(client)
    response = await client.get("/auth/oauth/github/callback", params={"code": "c", "state": nonce})
    assert response.status_code == 502
    assert "Unable to sign in with GitHub" in response.text


async def test_unverified_email_is_told_to_verify(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_github(monkeypatch, github_profile("unverified@dev.vetfab.local", pid="gh-u", verified=False))
    nonce = await start(client)
    response = await client.get("/auth/oauth/github/callback", params={"code": "c", "state": nonce})
    assert response.status_code == 400
    assert "verified email" in response.text
    assert client.cookies.get(REFRESH) is None


async def test_callback_targets_the_origin_from_the_start_request(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_github(monkeypatch, github_profile("ide-user@dev.vetfab.local", pid="gh-ide"))
    nonce = await start(client, redirect=f"{IDE}/p?x=1", state="ide-state")
    response = await client.get("/auth/oauth/github/callback", params={"code": "c", "state": nonce})
    assert response.headers["location"].startswith(f"{IDE}/handoff#")
    assert fragment_of(response)["redirect"] == "/p?x=1"
    assert fragment_of(response)["state"] == "ide-state"


@pytest.mark.parametrize("status", ["suspended", "rejected"])
async def test_inactive_account_is_refused(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, make_user: Callable[..., User], status: str
) -> None:
    make_user(f"{status}-oauth@dev.vetfab.local", status=status)
    fake_github(monkeypatch, github_profile(f"{status}-oauth@dev.vetfab.local", pid=f"gh-{status}"))
    nonce = await start(client)
    response = await client.get("/auth/oauth/github/callback", params={"code": "c", "state": nonce})
    assert response.status_code == 403
    assert "not active" in response.text
    assert client.cookies.get(REFRESH) is None


async def test_login_page_shows_configured_providers_only(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/login", params={"redirect": f"{IDE}/x", "state": "s9"})
    assert "Continue with GitHub" in response.text
    assert "Continue with Google" not in response.text
    assert 'href="/auth/oauth/github/start?redirect=https%3A%2F%2Fdemo.vetfab.ai%2Fx&amp;state=s9"' in response.text
    assert "LMS" not in response.text and "IDE" not in response.text, "the sign-in page names no product"


def oauth_failures(owner_url: str) -> list[tuple[str | None, str | None]]:
    with psycopg.connect(owner_url) as conn:
        rows = conn.execute(
            """SELECT metadata->>'reason', metadata->>'provider' FROM identity.audit
                WHERE action = 'signin_failed' AND metadata ? 'provider' ORDER BY id"""
        ).fetchall()
    return [(r[0], r[1]) for r in rows]


async def test_provider_failure_is_logged_and_audited(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, owner_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    fake_github(monkeypatch, OAuthError("provider", "token exchange failed: redirect_uri_mismatch"))
    before = oauth_failures(owner_url)
    nonce = await start(client)
    with caplog.at_level("WARNING", logger="identity.oauth"):
        await client.get("/auth/oauth/github/callback", params={"code": "c", "state": nonce})
    assert any("redirect_uri_mismatch" in r.getMessage() for r in caplog.records)
    assert oauth_failures(owner_url)[len(before) :] == [("oauth_provider", "github")]


async def test_no_verified_email_is_audited(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, owner_url: str
) -> None:
    fake_github(monkeypatch, github_profile("audit-unverified@dev.vetfab.local", pid="gh-au", verified=False))
    before = oauth_failures(owner_url)
    nonce = await start(client)
    await client.get("/auth/oauth/github/callback", params={"code": "c", "state": nonce})
    assert oauth_failures(owner_url)[len(before) :] == [("no_verified_email", "github")]


async def test_state_mismatch_is_logged(client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture) -> None:
    await start(client)
    with caplog.at_level("WARNING", logger="identity.oauth"):
        await client.get("/auth/oauth/github/callback", params={"code": "c", "state": "forged"})
    assert any("state" in r.getMessage() for r in caplog.records)
