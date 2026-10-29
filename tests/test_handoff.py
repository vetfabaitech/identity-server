"""SSO hand-off tickets over HTTP: issuance, binding, single use, expiry, revocation, destination and path safety."""

import asyncio
import base64
import hashlib
import json
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from identity.store import User
from tests.conftest import ORIGIN, PASSWORD, SAME_ORIGIN, build_app, client_for, make_settings

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

IDE, STAGING, OPS, RETIRED = (
    "https://ide.vetfab.ai",
    "https://stg.vetfab.ai",
    "https://ops.vetfab.ai",
    "https://old.vetfab.ai",
)
SECRETS = {
    "lms": "lms-secret",
    "ide": "ide-secret",
    "staging": "staging-secret",
    "ops": "ops-secret",
    "old": "old-secret",
}


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def service(sid: str, url: str, **extra: Any) -> dict[str, Any]:
    return {"id": sid, "display_name": sid.upper(), "base_url": url, "secret_sha256": sha(SECRETS[sid]), **extra}


REGISTRY = json.dumps(
    {
        "services": [
            service("lms", ORIGIN),
            service("ide", IDE),
            service("staging", STAGING, environment="staging"),
            service("ops", OPS, roles=["admin"]),
            service("old", RETIRED, enabled=False),
        ]
    }
)


def basic(service_id: str, secret: str | None = None) -> dict[str, str]:
    token = base64.b64encode(f"{service_id}:{secret or SECRETS[service_id]}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
async def client(login_url: str, pool: AsyncConnectionPool, keys_dir: Path) -> AsyncIterator[httpx.AsyncClient]:
    settings = make_settings(
        login_url, keys_dir, app_origins=",".join([ORIGIN, IDE, STAGING, OPS, RETIRED]), services=REGISTRY
    )
    async with client_for(build_app(settings, pool, keys_dir)) as c:
        yield c


async def sign_in(client: httpx.AsyncClient, user: User) -> None:
    data = {"email": user.email, "password": PASSWORD, "redirect": "/", "state": "s1"}
    response = await client.post("/auth/login", data=data, headers=SAME_ORIGIN)
    assert response.status_code == 303


async def issue(client: httpx.AsyncClient, target: str, return_to: str = "/", origin: str = ORIGIN) -> httpx.Response:
    return await client.post(
        "/auth/handoff", json={"target": target, "return_to": return_to}, headers={"origin": origin}
    )


async def redeem(client: httpx.AsyncClient, ticket: str, service_id: str = "ide", **kw: Any) -> httpx.Response:
    return await client.post("/auth/handoff/redeem", json={"ticket": ticket}, headers=basic(service_id, **kw))


@pytest.fixture
async def signed_in(client: httpx.AsyncClient, make_user: Callable[..., User]) -> User:
    user = make_user(password=PASSWORD)
    await sign_in(client, user)
    return user


# --------------------------------------------------------------------------- issuing


async def test_a_signed_in_person_gets_a_ticket_for_a_registered_destination(
    client: httpx.AsyncClient, signed_in: User
) -> None:
    response = await issue(client, "ide", "/workspace/7")
    assert response.status_code == 200
    body = response.json()
    assert body["redeem_url"] == f"{IDE}/handoff/redeem"  # from the registry, not from the request
    assert body["target"] == "ide" and body["expires_in"] == 60
    assert len(body["ticket"]) >= 40
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["cache-control"] == "no-store"


async def test_issuing_needs_a_session(client: httpx.AsyncClient) -> None:
    response = await issue(client, "ide")
    assert response.status_code == 401


async def test_issuing_does_not_rotate_the_refresh_cookie(client: httpx.AsyncClient, signed_in: User) -> None:
    before = dict(client.cookies)
    assert (await issue(client, "ide")).status_code == 200
    assert dict(client.cookies) == before
    assert (await client.post("/auth/session/token", headers={"origin": ORIGIN})).status_code == 200


@pytest.mark.parametrize("origin", ["https://evil.example", RETIRED])
async def test_only_a_registered_service_origin_may_start_a_hand_off(
    client: httpx.AsyncClient, signed_in: User, origin: str
) -> None:
    response = await issue(client, "ide", origin=origin)
    assert response.status_code == 403
    assert "ticket" not in response.text


async def test_a_page_with_no_origin_cannot_start_one(client: httpx.AsyncClient, signed_in: User) -> None:
    response = await client.post("/auth/handoff", json={"target": "ide", "return_to": "/"})
    assert response.status_code == 403


@pytest.mark.parametrize("target", ["nope", "old", "ops", "", "IDE", "../ide"])
async def test_unknown_disabled_and_restricted_destinations_look_the_same(
    client: httpx.AsyncClient, signed_in: User, target: str
) -> None:
    response = await issue(client, target)
    assert (response.status_code, response.json()) == (403, {"error": "target_unavailable"})


@pytest.mark.parametrize("body", [{}, {"target": 5}, {"target": "ide", "return_to": 3}, [], "x"])
async def test_malformed_requests_are_400(client: httpx.AsyncClient, signed_in: User, body: Any) -> None:
    response = await client.post("/auth/handoff", json=body, headers={"origin": ORIGIN})
    assert response.status_code == 400


async def test_the_body_must_be_json(client: httpx.AsyncClient, signed_in: User) -> None:
    response = await client.post(
        "/auth/handoff", content="target=ide", headers={"origin": ORIGIN, "content-type": "text/plain"}
    )
    assert response.status_code == 415


async def test_a_session_cannot_hoard_tickets(client: httpx.AsyncClient, signed_in: User) -> None:
    for _ in range(20):
        assert (await issue(client, "ide")).status_code == 200
    refused = await issue(client, "ide")
    assert refused.status_code == 429
    assert refused.headers["retry-after"]


async def test_preflight_is_for_registered_origins_only(client: httpx.AsyncClient) -> None:
    ok = await client.options("/auth/handoff", headers={"origin": IDE})
    assert ok.status_code == 204 and ok.headers["access-control-allow-origin"] == IDE
    assert (await client.options("/auth/handoff", headers={"origin": "https://evil.example"})).status_code == 403


# --------------------------------------------------------------------------- redeeming


async def test_the_destination_backend_redeems_a_ticket_for_the_person(
    client: httpx.AsyncClient, signed_in: User
) -> None:
    ticket = (await issue(client, "ide", "/workspace/7?tab=2")).json()["ticket"]
    response = await redeem(client, ticket)
    assert response.status_code == 200
    assert response.json() == {
        "user_id": str(signed_in.id),
        "source_service": "lms",
        "source_origin": ORIGIN,
        "return_path": "/workspace/7?tab=2",
    }


async def test_a_ticket_works_once(client: httpx.AsyncClient, signed_in: User) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    assert (await redeem(client, ticket)).status_code == 200
    again = await redeem(client, ticket)
    assert (again.status_code, again.json()) == (400, {"error": "invalid_ticket"})


async def test_racing_redemptions_produce_exactly_one_success(client: httpx.AsyncClient, signed_in: User) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    results = await asyncio.gather(*(redeem(client, ticket) for _ in range(12)))
    assert sorted(r.status_code for r in results) == [200] + [400] * 11


async def test_a_ticket_for_another_service_is_refused_and_burned(client: httpx.AsyncClient, signed_in: User) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    wrong = await redeem(client, ticket, "staging")  # staging is registered, with its own valid secret
    assert wrong.status_code == 400
    assert (await redeem(client, ticket, "ide")).status_code == 400  # a stolen ticket cannot be retried


async def test_the_source_cannot_redeem_its_own_ticket(client: httpx.AsyncClient, signed_in: User) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    assert (await redeem(client, ticket, "lms")).status_code == 400


async def test_tickets_for_the_staging_service_work_like_any_other(client: httpx.AsyncClient, signed_in: User) -> None:
    ticket = (await issue(client, "staging", "/lab")).json()["ticket"]
    response = await redeem(client, ticket, "staging")
    assert response.status_code == 200 and response.json()["return_path"] == "/lab"


@pytest.mark.parametrize(
    "mangle",
    [
        lambda t: t[:-1] + ("A" if t[-1] != "A" else "B"),
        lambda t: t[:30],
        lambda t: "",
        lambda t: t + "x" * 40,
        lambda t: "A" * 43,
    ],
)
async def test_tampered_and_unknown_tickets_are_refused(
    client: httpx.AsyncClient, signed_in: User, mangle: Callable[[str], str]
) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    assert (await redeem(client, mangle(ticket))).status_code == 400
    assert (await redeem(client, ticket)).status_code == 200  # the real one is untouched by guesses


@pytest.mark.parametrize("body", [{}, {"ticket": 5}, {"ticket": None}])
async def test_malformed_redemptions_are_400(client: httpx.AsyncClient, body: Any) -> None:
    response = await client.post("/auth/handoff/redeem", json=body, headers=basic("ide"))
    assert response.status_code == 400


async def test_a_ticket_expires(client: httpx.AsyncClient, signed_in: User, owner_url: str) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE identity.handoff_tickets SET expires_at = now() - interval '1 second'")
    assert (await redeem(client, ticket)).status_code == 400


async def test_signing_out_centrally_kills_outstanding_tickets(client: httpx.AsyncClient, signed_in: User) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    assert (await client.post("/auth/logout", headers=SAME_ORIGIN)).status_code == 303
    assert (await redeem(client, ticket)).status_code == 400


async def test_a_suspended_account_cannot_complete_a_hand_off(
    client: httpx.AsyncClient, signed_in: User, owner_url: str
) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE public.users SET status = 'suspended' WHERE id = %s", (signed_in.id,))
    assert (await redeem(client, ticket)).status_code == 400


@pytest.mark.parametrize(
    ("asked", "landed"),
    [
        ("/workspace/3", "/workspace/3"),
        ("//evil.example/x", "/"),
        ("https://evil.example/x", "/"),
        ("javascript:alert(1)", "/"),
        ("/handoff/redeem", "/"),
        ("/a/../../b", "/b"),
    ],
)
async def test_the_return_path_cannot_leave_the_destination(
    client: httpx.AsyncClient, signed_in: User, asked: str, landed: str
) -> None:
    ticket = (await issue(client, "ide", asked)).json()["ticket"]
    assert (await redeem(client, ticket)).json()["return_path"] == landed


# --------------------------------------------------------------------------- who may redeem


@pytest.mark.parametrize(
    "headers",
    [
        {},
        basic("ide", "wrong"),
        basic("lms", SECRETS["ide"]),  # another service's secret
        basic("old", "wrong"),  # a disabled service with the wrong secret learns nothing
        basic("nobody", "x"),
        {"Authorization": "Basic !!!"},
        {"Authorization": "Bearer ide-secret"},
    ],
)
async def test_redeeming_needs_the_destinations_own_secret(
    client: httpx.AsyncClient, signed_in: User, headers: dict[str, str]
) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    response = await client.post("/auth/handoff/redeem", json={"ticket": ticket}, headers=headers)
    assert response.status_code == 401
    assert (await redeem(client, ticket)).status_code == 200  # and a failed attempt did not spend it


async def test_a_disabled_service_with_its_own_secret_is_told_it_is_disabled(
    client: httpx.AsyncClient, signed_in: User
) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    response = await client.post("/auth/handoff/redeem", json={"ticket": ticket}, headers=basic("old"))
    assert (response.status_code, response.json()) == (403, {"error": "service_disabled"})
    assert (await redeem(client, ticket)).status_code == 200  # and nothing was spent


async def test_a_browser_cannot_call_the_redemption_route(client: httpx.AsyncClient, signed_in: User) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    response = await client.post(
        "/auth/handoff/redeem", json={"ticket": ticket}, headers={**basic("ide"), "origin": IDE}
    )
    assert "access-control-allow-origin" not in response.headers


# --------------------------------------------------------------------------- the list of services


async def test_the_switcher_list_shows_only_services_this_person_may_open(
    client: httpx.AsyncClient, signed_in: User
) -> None:
    response = await client.get("/auth/services", headers={"origin": ORIGIN})
    assert response.status_code == 200
    body = response.json()
    assert body["current"] == "lms"
    assert [s["id"] for s in body["services"]] == ["lms", "ide", "staging"]  # not "ops" (admin only), not "old"
    assert set(body["services"][1]) == {"id", "display_name", "base_url", "environment"}  # no secrets, no hashes


async def test_admins_see_restricted_services(
    client: httpx.AsyncClient, make_user: Callable[..., User], owner_url: str
) -> None:
    admin = make_user(password=PASSWORD)
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE public.users SET role = 'admin' WHERE id = %s", (admin.id,))
    await sign_in(client, admin)
    body = (await client.get("/auth/services", headers={"origin": ORIGIN})).json()
    assert "ops" in [s["id"] for s in body["services"]]
    assert (await issue(client, "ops")).status_code == 200


async def test_the_list_needs_a_session_and_an_allowed_origin(client: httpx.AsyncClient, signed_in: User) -> None:
    assert (await client.get("/auth/services", headers={"origin": "https://evil.example"})).status_code == 403
    client.cookies.clear()
    assert (await client.get("/auth/services", headers={"origin": ORIGIN})).status_code == 401


# --------------------------------------------------------------------------- secrecy


async def test_tickets_are_stored_hashed_and_never_audited(
    client: httpx.AsyncClient, signed_in: User, owner_url: str
) -> None:
    ticket = (await issue(client, "ide")).json()["ticket"]
    await redeem(client, ticket)
    await redeem(client, ticket)
    with psycopg.connect(owner_url, autocommit=True) as conn:
        stored = conn.execute("SELECT ticket_hash FROM identity.handoff_tickets").fetchall()
        audit = conn.execute(
            "SELECT action, metadata::text FROM identity.audit WHERE action LIKE 'handoff_%' ORDER BY id"
        ).fetchall()
    assert all(len(row[0]) == 32 and ticket.encode() not in bytes(row[0]) for row in stored)
    assert [a for a, _ in audit][-3:] == ["handoff_issued", "handoff_redeemed", "handoff_rejected"]
    assert not any(ticket in text for _, text in audit)
    assert any("reused" in text for _, text in audit)
