"""The backend adapter against the real identity service (real sign-in, real JWKS, real renewal and sign-out).

A product's protected API runs behind `IdentityGuard`; the "browser" is an httpx client that does what the JS client
does: sign in through the service, take the token from the hand-off fragment, renew from the refresh cookie, sign out.
Both apps run in-process over ASGI against the throwaway test database.
"""

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx
import pytest
from fastapi import Depends, FastAPI
from psycopg_pool import AsyncConnectionPool

from identity.config import Settings
from identity.store import User
from tests.conftest import ORIGIN, PASSWORD, SAME_ORIGIN, build_app, client_for
from vetfab_identity_adapter import AdapterConfig, IdentityAdapter, VerifiedIdentity
from vetfab_identity_adapter.fastapi import IdentityGuard

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

REFRESH = "__Secure-vf_refresh"


@dataclass
class Member:
    id: UUID
    is_admin: bool


@pytest.fixture
async def identity_client(
    settings: Settings, pool: AsyncConnectionPool, keys_dir: Path
) -> AsyncIterator[httpx.AsyncClient]:
    async with client_for(build_app(settings, pool, keys_dir)) as client:
        yield client


@pytest.fixture
async def product(identity_client: httpx.AsyncClient) -> AsyncIterator[tuple[httpx.AsyncClient, set[UUID]]]:
    """A product API protected by the adapter, fetching its keys from the running identity service."""
    admins: set[UUID] = set()
    config = AdapterConfig.build(auth_url=ORIGIN, environment="production")
    adapter = IdentityAdapter(config, http=identity_client)

    async def load_member(identity: VerifiedIdentity) -> Member:
        return Member(identity.user_id, identity.user_id in admins)

    guard: IdentityGuard[Member] = IdentityGuard(adapter, load_member)
    app = FastAPI()

    @app.get("/api/me")
    async def me(member: Member = Depends(guard.user)) -> dict[str, str]:
        return {"id": str(member.id)}

    @app.post("/api/admin")
    async def admin(member: Member = Depends(guard.require(lambda m: m.is_admin))) -> dict[str, str]:
        return {"ok": "yes"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://product.test") as api:
        yield api, admins


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def sign_in(client: httpx.AsyncClient, email: str) -> tuple[str, str]:
    """Signs in as the browser would and returns (access token, state echoed back)."""
    data = {"email": email, "password": PASSWORD, "redirect": f"{ORIGIN}/lab", "state": "state-from-this-tab"}
    response = await client.post("/auth/login", data=data, headers=SAME_ORIGIN)
    assert response.status_code == 303, response.text
    fragment = {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).fragment).items()}
    assert fragment["state"] == "state-from-this-tab"
    return fragment["token"], fragment["state"]


async def test_a_real_sign_in_token_opens_the_products_api(
    identity_client: httpx.AsyncClient, product: tuple[httpx.AsyncClient, set[UUID]], make_user: Callable[..., User]
) -> None:
    api, _ = product
    user = make_user(password=PASSWORD)
    token, _ = await sign_in(identity_client, user.email)
    response = await api.get("/api/me", headers=bearer(token))
    assert (response.status_code, response.json()) == (200, {"id": str(user.id)})


async def test_the_api_refuses_requests_without_a_valid_token(
    identity_client: httpx.AsyncClient, product: tuple[httpx.AsyncClient, set[UUID]], make_user: Callable[..., User]
) -> None:
    api, _ = product
    token, _ = await sign_in(identity_client, make_user(password=PASSWORD).email)
    assert (await api.get("/api/me")).status_code == 401
    assert (await api.get("/api/me", headers=bearer(token[:-4] + "AAAA"))).status_code == 401
    assert (await api.get("/api/me", headers=bearer("garbage"))).status_code == 401


async def test_a_signed_in_person_is_not_an_administrator(
    identity_client: httpx.AsyncClient, product: tuple[httpx.AsyncClient, set[UUID]], make_user: Callable[..., User]
) -> None:
    api, admins = product
    user = make_user(password=PASSWORD)
    token, _ = await sign_in(identity_client, user.email)
    assert (await api.post("/api/admin", headers=bearer(token))).status_code == 403
    admins.add(user.id)  # the product's own authorisation changes; the token does not
    assert (await api.post("/api/admin", headers=bearer(token))).status_code == 200


async def test_the_refresh_cookie_renews_and_sign_out_ends_it(
    identity_client: httpx.AsyncClient, product: tuple[httpx.AsyncClient, set[UUID]], make_user: Callable[..., User]
) -> None:
    api, _ = product
    user = make_user(password=PASSWORD)
    await sign_in(identity_client, user.email)
    assert identity_client.cookies.get(REFRESH)

    renewed = await identity_client.post("/auth/session/token", headers={"origin": ORIGIN})
    assert renewed.status_code == 200
    fresh = renewed.json()["access_token"]
    assert (await api.get("/api/me", headers=bearer(fresh))).status_code == 200

    out = await identity_client.post("/auth/logout", params={"redirect": f"{ORIGIN}/"}, headers=SAME_ORIGIN)
    assert out.status_code == 303
    refused = await identity_client.post("/auth/session/token", headers={"origin": ORIGIN})
    assert refused.status_code == 401


async def test_a_suspended_account_gets_no_new_tokens(
    identity_client: httpx.AsyncClient, make_user: Callable[..., User], owner_url: str
) -> None:
    import psycopg

    user = make_user(password=PASSWORD)
    await sign_in(identity_client, user.email)
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE public.users SET status = 'suspended' WHERE id = %s", (user.id,))
    refused = await identity_client.post("/auth/session/token", headers={"origin": ORIGIN})
    assert refused.status_code == 401
