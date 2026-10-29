"""With IDENTITY_SILENT_SIGN_IN=false a live session never signs a person in to the next service without asking."""

from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
from psycopg_pool import AsyncConnectionPool

from identity.store import User
from tests.conftest import PASSWORD, build_app, client_for, make_settings
from tests.test_http import REFRESH, handoff, sign_in

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

QUERY = {"redirect": "/teach", "state": "s2"}


@pytest.fixture
async def client(login_url: str, pool: AsyncConnectionPool, keys_dir: Path) -> AsyncIterator[httpx.AsyncClient]:
    settings = make_settings(login_url, keys_dir, silent_sign_in=False)
    async with client_for(build_app(settings, pool, keys_dir)) as c:
        yield c


async def test_a_live_session_still_gets_the_sign_in_page(
    client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    user = make_user(password=PASSWORD)
    handoff(await sign_in(client, user.email))  # signing in itself lands at once
    session = client.cookies.get(REFRESH)
    response = await client.get("/auth/login", params=QUERY)
    assert response.status_code == 200 and "location" not in response.headers
    assert 'name="password"' in response.text
    assert 'name="redirect" value="/teach"' in response.text and 'name="state" value="s2"' in response.text
    assert "token" not in response.text
    assert client.cookies.get(REFRESH) == session  # looking at the page changes nothing


async def test_signing_in_again_as_someone_else_replaces_the_session(
    client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    first, second = make_user(password=PASSWORD), make_user(password=PASSWORD)
    handoff(await sign_in(client, first.email))
    before = client.cookies.get(REFRESH)
    fragment = handoff(await sign_in(client, second.email, **QUERY))
    assert fragment["redirect"] == "/teach" and fragment["token"]
    assert client.cookies.get(REFRESH) not in (None, before)
