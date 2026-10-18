"""Sign-in, silent renewal, logout and JWKS over HTTP (spec §3.1)."""

import json
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from psycopg_pool import AsyncConnectionPool

from identity.config import Settings
from identity.keys import KeyRing
from identity.store import User
from tests.conftest import ORIGIN, PASSWORD, SAME_ORIGIN, build_app, client_for, make_settings
from vetfab_authz.tokens import JwksKeyStore, JwksSource, TokenPolicy, TokenVerifier

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

REFRESH = "__Secure-vf_refresh"


@pytest.fixture
async def client(settings: Settings, pool: AsyncConnectionPool, keys_dir: Path) -> AsyncIterator[httpx.AsyncClient]:
    async with client_for(build_app(settings, pool, keys_dir)) as c:
        yield c


def handoff(response: httpx.Response) -> dict[str, str]:
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith(f"{ORIGIN}/handoff#"), location
    return {k: v[0] for k, v in parse_qs(urlsplit(location).fragment).items()}


async def verify(token: str, keys_dir: Path, tmp_path: Path) -> str:
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps(KeyRing.load(keys_dir).jwks()))
    verifier = TokenVerifier(
        TokenPolicy(issuer="https://test.vetfab.ai/auth", audience="vetfab"), JwksKeyStore(JwksSource(file=jwks))
    )
    return str((await verifier.verify(token)).user_id)


async def sign_in(client: httpx.AsyncClient, email: str, password: str = PASSWORD, **form: str) -> httpx.Response:
    data = {"email": email, "password": password, "redirect": "/learn", "state": "s1", **form}
    return await client.post("/auth/login", data=data, headers=SAME_ORIGIN)


async def test_the_sign_in_page_carries_redirect_and_state(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/login", params={"redirect": "/learn/kits", "state": "abc"})
    assert response.status_code == 200
    assert 'name="redirect" value="/learn/kits"' in response.text
    assert 'name="state" value="abc"' in response.text
    assert response.headers["cache-control"] == "no-store"
    csp = response.headers["content-security-policy"]
    assert "form-action 'self' https://test.vetfab.ai" in csp
    assert "frame-ancestors 'none'" in csp
    # `no-referrer` would make browsers send `Origin: null` on the form post, failing the same-origin check.
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"


async def test_password_sign_in_hands_off_a_verified_token(
    client: httpx.AsyncClient, make_user: Callable[..., User], keys_dir: Path, tmp_path: Path, owner_url: str
) -> None:
    user = make_user(password=PASSWORD)
    response = await sign_in(client, user.email.upper())
    fragment = handoff(response)
    assert fragment["redirect"] == "/learn"
    assert fragment["state"] == "s1"
    assert await verify(fragment["token"], keys_dir, tmp_path) == str(user.id)
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{REFRESH}=")
    for attribute in ("Path=/auth", "HttpOnly", "Secure", "SameSite=lax"):
        assert attribute.lower() in cookie.lower()


@pytest.mark.parametrize("which", ["wrong password", "unknown email"])
async def test_failed_sign_in_says_the_same_thing(
    client: httpx.AsyncClient, make_user: Callable[..., User], which: str
) -> None:
    user = make_user(password=PASSWORD)
    email = user.email if which == "wrong password" else "nobody@dev.vetfab.local"
    response = await sign_in(client, email, password="not the password")
    assert response.status_code == 401
    assert "Email or password is incorrect." in response.text
    assert "set-cookie" not in response.headers


async def test_too_many_failures_are_refused_even_with_the_right_password(
    settings: Settings, pool: AsyncConnectionPool, keys_dir: Path, login_url: str, make_user: Callable[..., User]
) -> None:
    strict = make_settings(login_url, keys_dir, rate_limit_attempts=3)
    user = make_user(password=PASSWORD)
    async with client_for(build_app(strict, pool, keys_dir)) as client:
        for _ in range(3):
            assert (await sign_in(client, user.email, password="nope nope nope")).status_code == 401
        refused = await sign_in(client, user.email)
    assert refused.status_code == 429
    assert "Too many attempts" in refused.text


@pytest.mark.parametrize("status", ["suspended", "rejected"])
async def test_inactive_accounts_cannot_sign_in(
    client: httpx.AsyncClient, make_user: Callable[..., User], status: str
) -> None:
    user = make_user(status=status, password=PASSWORD)
    response = await sign_in(client, user.email)
    assert response.status_code == 403
    assert "not active" in response.text
    assert "set-cookie" not in response.headers


async def test_pending_accounts_sign_in(client: httpx.AsyncClient, make_user: Callable[..., User]) -> None:
    user = make_user(status="pending", password=PASSWORD)
    handoff(await sign_in(client, user.email))


@pytest.mark.parametrize(
    "headers",
    [
        {"origin": "https://evil.example", "sec-fetch-site": "cross-site"},
        {"origin": ORIGIN, "sec-fetch-site": "same-site"},
        {},
    ],
)
async def test_cross_site_posts_are_refused(
    client: httpx.AsyncClient, make_user: Callable[..., User], headers: dict[str, str]
) -> None:
    user = make_user(password=PASSWORD)
    response = await client.post(
        "/auth/login", data={"email": user.email, "password": PASSWORD, "redirect": "/"}, headers=headers
    )
    assert response.status_code == 403
    assert "set-cookie" not in response.headers


async def test_a_refresh_cookie_signs_in_silently_and_rotates(
    client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    user = make_user(password=PASSWORD)
    first = client.cookies.get(REFRESH) if (await sign_in(client, user.email)) else None
    assert first
    response = await client.get("/auth/login", params={"redirect": "/teach", "state": "s2"})
    fragment = handoff(response)
    assert fragment["redirect"] == "/teach" and fragment["state"] == "s2"
    assert client.cookies.get(REFRESH) not in (None, first)


async def test_a_suspended_account_loses_its_silent_sign_in(
    client: httpx.AsyncClient, make_user: Callable[..., User], owner_url: str
) -> None:
    import psycopg

    user = make_user(password=PASSWORD)
    handoff(await sign_in(client, user.email))
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE public.users SET status = 'suspended' WHERE id = %s", (user.id,))
    response = await client.get("/auth/login", params={"redirect": "/learn"})
    assert response.status_code == 200
    assert "not active" in response.text
    assert 'name="password"' in response.text
    assert client.cookies.get(REFRESH) is None


async def test_logout_revokes_and_returns_to_the_given_path(
    client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    user = make_user(password=PASSWORD)
    handoff(await sign_in(client, user.email))
    stolen = client.cookies.get(REFRESH)
    response = await client.post("/auth/logout", params={"redirect": "/signout?done=1"}, headers=SAME_ORIGIN)
    assert response.status_code == 303
    assert response.headers["location"] == "/signout?done=1"
    assert client.cookies.get(REFRESH) is None
    client.cookies.set(REFRESH, stolen or "", domain="test.vetfab.ai", path="/auth")
    after = await client.get("/auth/login", params={"redirect": "/learn"})
    assert after.status_code == 200 and 'name="password"' in after.text, "the old cookie no longer signs in"


async def test_logout_refuses_cross_site_and_get(client: httpx.AsyncClient) -> None:
    cross = await client.post(
        "/auth/logout", headers={"origin": "https://evil.example", "sec-fetch-site": "cross-site"}
    )
    assert cross.status_code == 403
    assert (await client.get("/auth/logout")).status_code == 405


async def test_logout_never_redirects_off_site(client: httpx.AsyncClient) -> None:
    response = await client.post("/auth/logout", params={"redirect": "//evil.example/x"}, headers=SAME_ORIGIN)
    assert response.headers["location"] == "/"


async def test_redirects_are_kept_on_site(client: httpx.AsyncClient, make_user: Callable[..., User]) -> None:
    user = make_user(password=PASSWORD)
    fragment = handoff(await sign_in(client, user.email, redirect="//evil.example", state="<bad>"))
    assert fragment["redirect"] == "/"
    assert "state" not in fragment


async def test_jwks_publishes_the_signing_key(client: httpx.AsyncClient, keys_dir: Path) -> None:
    response = await client.get("/auth/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    kids = [k["kid"] for k in response.json()["keys"]]
    assert KeyRing.load(keys_dir).signing_kid in kids


async def test_health(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/health")
    assert response.status_code == 200 and response.json() == {"status": "ok"}


async def test_large_bodies_are_refused(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/login",
        content=b"x" * 40_000,
        headers={**SAME_ORIGIN, "content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413


IDE = "https://demo.vetfab.ai"


@pytest.fixture
async def two_origin_client(
    login_url: str, pool: AsyncConnectionPool, keys_dir: Path
) -> AsyncIterator[httpx.AsyncClient]:
    settings = make_settings(login_url, keys_dir, app_origins=f"{ORIGIN},{IDE}")
    async with client_for(build_app(settings, pool, keys_dir)) as c:
        yield c


async def test_handoff_can_land_on_another_allowlisted_origin(
    two_origin_client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    user = make_user(password=PASSWORD)
    response = await sign_in(two_origin_client, user.email, redirect=f"{IDE}/projects")
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(f"{IDE}/handoff#"), location
    fragment = {k: v[0] for k, v in parse_qs(urlsplit(location).fragment).items()}
    assert fragment["redirect"] == "/projects"
    assert fragment["state"] == "s1"


async def test_the_sign_in_page_echoes_an_absolute_target(two_origin_client: httpx.AsyncClient) -> None:
    response = await two_origin_client.get("/auth/login", params={"redirect": f"{IDE}/p?x=1"})
    assert 'name="redirect" value="https://demo.vetfab.ai/p?x=1"' in response.text


async def test_a_foreign_absolute_target_lands_on_the_default_origin(
    two_origin_client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    user = make_user(password=PASSWORD)
    response = await sign_in(two_origin_client, user.email, redirect="https://evil.example/x")
    assert response.headers["location"].startswith(f"{ORIGIN}/handoff#")


async def test_the_ide_signs_out_through_a_same_site_post(
    two_origin_client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    user = make_user(password=PASSWORD)
    handoff(await sign_in(two_origin_client, user.email))
    raw = two_origin_client.cookies.get(REFRESH)
    response = await two_origin_client.post(
        "/auth/logout",
        params={"redirect": f"{IDE}/signed-out"},
        headers={"origin": IDE, "sec-fetch-site": "same-site"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"{IDE}/signed-out"
    two_origin_client.cookies.set(REFRESH, raw or "", domain="test.vetfab.ai", path="/auth")
    after = await two_origin_client.get("/auth/login")
    assert after.status_code == 200 and 'name="password"' in after.text, "the session is revoked"


# --------------------------------------------------------------------------- XHR renewal (spec SI-4)


async def test_renewal_returns_a_verified_token_and_rotates(
    two_origin_client: httpx.AsyncClient, make_user: Callable[..., User], keys_dir: Path, tmp_path: Path
) -> None:
    user = make_user(password=PASSWORD)
    handoff(await sign_in(two_origin_client, user.email))
    first = two_origin_client.cookies.get(REFRESH)
    response = await two_origin_client.post("/auth/session/token", headers={"origin": IDE})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["expires_in"] == 900
    assert await verify(body["access_token"], keys_dir, tmp_path) == str(user.id)
    assert response.headers["access-control-allow-origin"] == IDE
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["cache-control"] == "no-store"
    assert two_origin_client.cookies.get(REFRESH) not in (None, first), "the refresh token rotated"


async def test_renewal_refuses_other_origins(
    two_origin_client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    user = make_user(password=PASSWORD)
    handoff(await sign_in(two_origin_client, user.email))
    before = two_origin_client.cookies.get(REFRESH)
    for headers in ({"origin": "https://evil.example"}, {}):
        response = await two_origin_client.post("/auth/session/token", headers=headers)
        assert response.status_code == 403
        assert "access-control-allow-origin" not in response.headers
    assert two_origin_client.cookies.get(REFRESH) == before
    assert (await two_origin_client.post("/auth/session/token", headers={"origin": IDE})).status_code == 200


async def test_renewal_without_cookie_is_401(two_origin_client: httpx.AsyncClient) -> None:
    response = await two_origin_client.post("/auth/session/token", headers={"origin": IDE})
    assert response.status_code == 401
    assert response.json() == {"error": "unknown"}
    assert response.headers["access-control-allow-origin"] == IDE, "so the IDE can read the 401"


async def test_renewal_after_sign_out_is_401(
    two_origin_client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    user = make_user(password=PASSWORD)
    handoff(await sign_in(two_origin_client, user.email))
    raw = two_origin_client.cookies.get(REFRESH)
    await two_origin_client.post("/auth/logout", headers={"origin": IDE, "sec-fetch-site": "same-site"})
    two_origin_client.cookies.set(REFRESH, raw or "", domain="test.vetfab.ai", path="/auth")
    response = await two_origin_client.post("/auth/session/token", headers={"origin": IDE})
    assert response.status_code == 401
    assert response.json() == {"error": "revoked"}


async def test_renewal_preflight(two_origin_client: httpx.AsyncClient) -> None:
    ok = await two_origin_client.options(
        "/auth/session/token", headers={"origin": IDE, "access-control-request-method": "POST"}
    )
    assert ok.status_code == 204
    assert ok.headers["access-control-allow-origin"] == IDE
    assert ok.headers["access-control-allow-methods"] == "POST"
    assert ok.headers["access-control-max-age"] == "600"
    refused = await two_origin_client.options("/auth/session/token", headers={"origin": "https://evil.example"})
    assert refused.status_code == 403
    assert "access-control-allow-origin" not in refused.headers
