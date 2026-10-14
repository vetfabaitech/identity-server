"""Test-accounts mode (spec TD-9): passphrase-gated, only the configured accounts, off unless switched on."""

from collections.abc import AsyncIterator, Callable
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from psycopg_pool import AsyncConnectionPool

from identity.config import Settings
from identity.store import User
from tests.conftest import ORIGIN, SAME_ORIGIN, build_app, client_for, make_settings

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

PASSPHRASE = "let the testers in please"  # noqa: S105  # test fixture
ADMIN = "picker-admin@dev.vetfab.local"
LEARNER = "picker-learner@dev.vetfab.local"


@pytest.fixture
def accounts(make_user: Callable[..., User]) -> dict[str, User]:
    return {
        "learner": make_user(LEARNER, name="Lina Learner"),
        "admin": make_user(ADMIN, name="Asha Admin"),
        "outsider": make_user(name="Not Listed"),
    }


@pytest.fixture
def picker_settings(login_url: str, keys_dir: Path) -> Settings:
    return make_settings(
        login_url,
        keys_dir,
        test_accounts=True,
        test_accounts_passphrase=PASSPHRASE,
        test_accounts_emails=f"{ADMIN},{LEARNER}",
        rate_limit_attempts=3,
    )


@pytest.fixture
async def client(
    picker_settings: Settings, pool: AsyncConnectionPool, keys_dir: Path
) -> AsyncIterator[httpx.AsyncClient]:
    async with client_for(build_app(picker_settings, pool, keys_dir)) as c:
        yield c


async def unlock(client: httpx.AsyncClient, passphrase: str = PASSPHRASE) -> httpx.Response:
    return await client.post(
        "/auth/test-accounts",
        data={"passphrase": passphrase, "redirect": "/learn", "state": "s9"},
        headers=SAME_ORIGIN,
    )


async def test_the_mode_is_off_by_default(settings: Settings, pool: AsyncConnectionPool, keys_dir: Path) -> None:
    async with client_for(build_app(settings, pool, keys_dir)) as client:
        assert (await client.get("/auth/test-accounts")).status_code == 404
        assert (
            await client.post("/auth/test-accounts", data={"passphrase": "x"}, headers=SAME_ORIGIN)
        ).status_code == 404
        page = await client.get("/auth/login")
    assert "/auth/test-accounts" not in page.text


async def test_the_sign_in_page_links_to_the_picker_when_on(client: httpx.AsyncClient) -> None:
    page = await client.get("/auth/login", params={"redirect": "/learn", "state": "s9"})
    assert "/auth/test-accounts?redirect=%2Flearn&amp;state=s9" in page.text


async def test_the_picker_asks_for_the_passphrase_first(client: httpx.AsyncClient, accounts: dict[str, User]) -> None:
    page = await client.get("/auth/test-accounts")
    assert page.status_code == 200
    assert 'name="passphrase"' in page.text
    assert ADMIN not in page.text


async def test_a_wrong_passphrase_is_refused_and_counted(client: httpx.AsyncClient) -> None:
    for _ in range(3):
        assert (await unlock(client, "not the passphrase")).status_code == 401
    assert (await unlock(client)).status_code == 429


async def test_the_right_passphrase_lists_exactly_the_configured_accounts(
    client: httpx.AsyncClient, accounts: dict[str, User]
) -> None:
    unlocked = await unlock(client)
    assert unlocked.status_code == 303
    assert unlocked.headers["location"] == "/auth/test-accounts?redirect=%2Flearn&state=s9"
    page = await client.get(unlocked.headers["location"])
    assert page.status_code == 200
    assert page.text.index(ADMIN) < page.text.index(LEARNER), "configured order"
    assert "Not Listed" not in page.text
    assert 'name="state" value="s9"' in page.text


async def test_signing_in_as_a_listed_account(client: httpx.AsyncClient, accounts: dict[str, User]) -> None:
    await unlock(client)
    response = await client.post(
        "/auth/test-accounts/signin",
        data={"user_id": str(accounts["admin"].id), "redirect": "/admin", "state": "s9"},
        headers=SAME_ORIGIN,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(f"{ORIGIN}/handoff#")
    fragment = {k: v[0] for k, v in parse_qs(urlsplit(location).fragment).items()}
    assert fragment["redirect"] == "/admin" and fragment["state"] == "s9"
    assert response.headers["set-cookie"].startswith("__Secure-vf_refresh=")


async def test_signing_in_needs_the_pass_cookie(client: httpx.AsyncClient, accounts: dict[str, User]) -> None:
    response = await client.post(
        "/auth/test-accounts/signin", data={"user_id": str(accounts["admin"].id)}, headers=SAME_ORIGIN
    )
    assert response.status_code == 403


async def test_an_unlisted_account_cannot_be_chosen(client: httpx.AsyncClient, accounts: dict[str, User]) -> None:
    await unlock(client)
    for user_id in (str(accounts["outsider"].id), "not-a-uuid"):
        response = await client.post("/auth/test-accounts/signin", data={"user_id": user_id}, headers=SAME_ORIGIN)
        assert response.status_code == 404


async def test_picker_posts_are_same_origin_only(client: httpx.AsyncClient, accounts: dict[str, User]) -> None:
    await unlock(client)
    response = await client.post(
        "/auth/test-accounts/signin",
        data={"user_id": str(accounts["admin"].id)},
        headers={"origin": "https://evil.example", "sec-fetch-site": "cross-site"},
    )
    assert response.status_code == 403
