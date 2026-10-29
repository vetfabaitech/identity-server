"""Protected endpoints: authentication failures, authorisation failures, outages, and that nothing leaks."""

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from uuid import UUID

import httpx
import pytest
from fastapi import Depends, FastAPI

from fakes import FakeIdentity, Signer
from vetfab_identity_adapter import IdentityAdapter, VerifiedIdentity
from vetfab_identity_adapter.fastapi import IdentityGuard


@dataclass
class User:
    id: UUID
    role: str


ADMIN, MEMBER = "00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000b2"
UNKNOWN = "00000000-0000-4000-8000-0000000000ff"
USERS = {UUID(ADMIN): User(UUID(ADMIN), "admin"), UUID(MEMBER): User(UUID(MEMBER), "member")}


@pytest.fixture
async def client(adapter: IdentityAdapter) -> AsyncIterator[httpx.AsyncClient]:
    async def load_user(identity: VerifiedIdentity) -> User | None:
        return USERS.get(identity.user_id)

    guard: IdentityGuard[User] = IdentityGuard(adapter, load_user)
    app = FastAPI()

    @app.get("/whoami")
    async def whoami(identity: VerifiedIdentity = Depends(guard.identity)) -> dict[str, str]:
        return {"id": str(identity.user_id)}

    @app.get("/me")
    async def me(user: User = Depends(guard.user)) -> dict[str, str]:
        return {"role": user.role}

    @app.post("/admin")
    async def admin(
        user: User = Depends(guard.require(lambda u: u.role == "admin", "admin_required")),
    ) -> dict[str, str]:
        return {"ok": "yes"}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://app") as http:
        yield http


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_unauthenticated_request_is_401_with_a_challenge(client: httpx.AsyncClient) -> None:
    response = await client.get("/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {"detail": {"code": "not_authenticated"}}


@pytest.mark.parametrize("header", ["Basic abc", "Bearer", "Bearer a b", "bearer", "Token abc"])
async def test_wrong_authorization_shapes_are_401(client: httpx.AsyncClient, header: str) -> None:
    assert (await client.get("/me", headers={"Authorization": header})).status_code == 401


async def test_invalid_token_is_401_and_not_echoed(client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    token = Signer.new().token(sub=MEMBER)
    response = await client.get("/me", headers=auth(token))
    assert response.status_code == 401
    assert response.json() == {"detail": {"code": "invalid_token"}}
    assert 'error="invalid_token"' in response.headers["www-authenticate"]
    assert token not in response.text
    assert token not in caplog.text


async def test_valid_token_reaches_the_application(client: httpx.AsyncClient, identity: FakeIdentity) -> None:
    response = await client.get("/me", headers=auth(identity.signer.token(sub=MEMBER)))
    assert (response.status_code, response.json()) == (200, {"role": "member"})


async def test_identity_dependency_needs_no_user_record(client: httpx.AsyncClient, identity: FakeIdentity) -> None:
    response = await client.get("/whoami", headers=auth(identity.signer.token(sub=UNKNOWN)))
    assert response.json() == {"id": UNKNOWN}


async def test_valid_identity_without_an_account_is_403(client: httpx.AsyncClient, identity: FakeIdentity) -> None:
    response = await client.get("/me", headers=auth(identity.signer.token(sub=UNKNOWN)))
    assert (response.status_code, response.json()) == (403, {"detail": {"code": "account_not_provisioned"}})


async def test_authenticated_is_not_authorised(client: httpx.AsyncClient, identity: FakeIdentity) -> None:
    denied = await client.post("/admin", headers=auth(identity.signer.token(sub=MEMBER)))
    assert (denied.status_code, denied.json()) == (403, {"detail": {"code": "admin_required"}})
    allowed = await client.post("/admin", headers=auth(identity.signer.token(sub=ADMIN)))
    assert allowed.status_code == 200


async def test_anonymous_cannot_reach_admin(client: httpx.AsyncClient) -> None:
    assert (await client.post("/admin")).status_code == 401


async def test_identity_outage_is_503_not_401(client: httpx.AsyncClient, identity: FakeIdentity) -> None:
    identity.down = True
    response = await client.get("/me", headers=auth(identity.signer.token(sub=MEMBER)))
    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"
    assert response.json() == {"detail": {"code": "identity_unavailable"}}
