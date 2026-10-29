"""SSO hand-off across independently authenticated services.

The real identity service runs in-process with a registry of three services (LMS, IDE, staging). Each is its own
FastAPI app built from the adapter: its own session key, its own users and roles, its own redemption secret. The
"browser" is an httpx client that does what the SDK does: asks the identity service for a ticket from the source page
(`Origin` = source), then POSTs the ticket as a form to the destination, which redeems it server to server.
"""

import hashlib
import json
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import pytest
from fastapi import Depends, FastAPI
from psycopg_pool import AsyncConnectionPool

from identity.store import User
from tests.conftest import ORIGIN, PASSWORD, SAME_ORIGIN, build_app, client_for, make_settings
from vetfab_identity_adapter import (
    AdapterConfig,
    HandoffConfig,
    HandoffRedeemer,
    IdentityAdapter,
    SessionCookie,
    VerifiedIdentity,
)
from vetfab_identity_adapter.fastapi import IdentityGuard, handoff_router

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

LMS, IDE, STAGING = ORIGIN, "https://ide.vetfab.ai", "https://stg.vetfab.ai"
SERVICE_SECRETS = {"lms": "lms-redeem-secret", "ide": "ide-redeem-secret", "staging": "staging-redeem-secret"}


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


REGISTRY = json.dumps(
    {
        "services": [
            {"id": sid, "display_name": sid.upper(), "base_url": url, "secret_sha256": sha(SERVICE_SECRETS[sid])}
            | ({"environment": "staging"} if sid == "staging" else {})
            for sid, url in (("lms", LMS), ("ide", IDE), ("staging", STAGING))
        ]
    }
)


@dataclass
class Product:
    """One service's backend. `members` is its own user table: id -> role."""

    id: str
    origin: str
    http: httpx.AsyncClient
    members: dict[UUID, str] = field(default_factory=dict)
    session_key: str = ""

    def cookie_name(self) -> str:
        return f"__Host-vf_session_{self.id}"


def build_product(
    service_id: str, origin: str, identity_app: Any, *, secret: str | None = None, down: bool = False
) -> tuple[FastAPI, dict[UUID, str]]:
    members: dict[UUID, str] = {}
    adapter_config = AdapterConfig.build(auth_url=ORIGIN, environment="production")
    config = HandoffConfig.build(
        adapter_config,
        service_id=service_id,
        service_secret=secret or SERVICE_SECRETS[service_id],
        session_secret=f"{service_id}-session-key-" + "x" * 30,  # each service has its own, never shared
        app_url=origin,
    )

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("identity unreachable")

    transport = httpx.MockTransport(refuse) if down else httpx.ASGITransport(app=identity_app)
    identity = httpx.AsyncClient(transport=transport, base_url=ORIGIN)
    sessions = SessionCookie(config)
    redeemer = HandoffRedeemer(adapter_config, config, http=identity)
    adapter = IdentityAdapter(adapter_config, http=identity)

    async def load_user(identity: VerifiedIdentity) -> str | None:
        return members.get(identity.user_id)  # this service's own record, with this service's own role

    guard: IdentityGuard[str] = IdentityGuard(adapter, load_user, sessions=sessions, app_origin=origin)
    app = FastAPI()
    app.include_router(handoff_router(redeemer, sessions, load_user, app_origin=origin))

    @app.get("/api/me")
    async def me(
        identity: VerifiedIdentity = Depends(guard.identity), role: str = Depends(guard.user)
    ) -> dict[str, str]:
        return {"service": service_id, "id": str(identity.user_id), "role": role}

    @app.post("/api/note")
    async def note(role: str = Depends(guard.user)) -> dict[str, str]:
        return {"saved": "yes"}

    @app.post("/api/admin")
    async def admin(role: str = Depends(guard.require(lambda r: r == "admin", "admin_required"))) -> dict[str, str]:
        return {"ok": "yes"}

    return app, members


@pytest.fixture
async def world(
    login_url: str, pool: AsyncConnectionPool, keys_dir: Path
) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, Product], Any]]:
    settings = make_settings(login_url, keys_dir, app_origins=",".join([LMS, IDE, STAGING]), services=REGISTRY)
    identity_app = build_app(settings, pool, keys_dir)
    async with client_for(identity_app) as browser_identity:
        products: dict[str, Product] = {}
        clients: list[httpx.AsyncClient] = []
        for sid, origin in (("lms", LMS), ("ide", IDE), ("staging", STAGING)):
            app, members = build_product(sid, origin, identity_app)
            http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=origin)
            clients.append(http)
            products[sid] = Product(sid, origin, http, members)
        try:
            yield browser_identity, products, identity_app
        finally:
            for c in clients:
                await c.aclose()


async def signed_in_person(
    browser: httpx.AsyncClient, make_user: Callable[..., User], products: dict[str, Product], roles: dict[str, str]
) -> User:
    """A person with a central session, and the role (if any) each service gives them in its own records."""
    user = make_user(password=PASSWORD)
    response = await browser.post(
        "/auth/login",
        data={"email": user.email, "password": PASSWORD, "redirect": "/", "state": "s"},
        headers=SAME_ORIGIN,
    )
    assert response.status_code == 303
    for service_id, role in roles.items():
        products[service_id].members[user.id] = role
    return user


async def ticket_for(browser: httpx.AsyncClient, source: Product, target: str, return_to: str = "/") -> dict[str, Any]:
    response = await browser.post(
        "/auth/handoff", json={"target": target, "return_to": return_to}, headers={"origin": source.origin}
    )
    assert response.status_code == 200, response.text
    return response.json()


async def deliver(
    destination: Product, ticket: str, *, origin: str | None, path: str = "/handoff/redeem"
) -> httpx.Response:
    headers = {"content-type": "application/x-www-form-urlencoded"}
    if origin is not None:
        headers["origin"] = origin
    return await destination.http.post(path, content=f"ticket={ticket}", headers=headers)


def session_cookie(response: httpx.Response) -> str | None:
    header = response.headers.get("set-cookie", "")
    return header.split(";")[0].split("=", 1)[1] if header.startswith("__Host-vf_session_") else None


async def open_service(destination: Product, cookie: str, path: str = "/api/me", method: str = "GET") -> httpx.Response:
    return await destination.http.request(
        method,
        path,
        cookies={destination.cookie_name(): cookie},
        headers={"origin": destination.origin} if method != "GET" else {},
    )


# --------------------------------------------------------------------------- the journeys


async def test_lms_to_ide(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    user = await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    grant = await ticket_for(browser, products["lms"], "ide", "/workspace/7")
    assert grant["redeem_url"] == f"{IDE}/handoff/redeem"
    landed = await deliver(products["ide"], grant["ticket"], origin=LMS)
    assert landed.status_code == 303 and landed.headers["location"] == "/workspace/7"
    assert landed.headers["referrer-policy"] == "no-referrer" and landed.headers["cache-control"] == "no-store"
    set_cookie = landed.headers["set-cookie"].lower()
    for attribute in ("httponly", "secure", "samesite=lax", "path=/"):
        assert attribute in set_cookie
    assert "domain" not in set_cookie  # host-only: never sent to a sibling subdomain
    cookie = session_cookie(landed)
    assert cookie and grant["ticket"] not in cookie
    me = await open_service(products["ide"], cookie)
    assert (me.status_code, me.json()) == (200, {"service": "ide", "id": str(user.id), "role": "member"})


async def test_ide_to_lms(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    user = await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    grant = await ticket_for(browser, products["ide"], "lms", "/courses")
    landed = await deliver(products["lms"], grant["ticket"], origin=IDE)
    assert landed.status_code == 303 and landed.headers["location"] == "/courses"
    cookie = session_cookie(landed)
    assert cookie
    assert (await open_service(products["lms"], cookie)).json()["id"] == str(user.id)


async def test_lms_to_an_authorised_staging_service(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "staging": "member"})
    grant = await ticket_for(browser, products["lms"], "staging")
    assert session_cookie(await deliver(products["staging"], grant["ticket"], origin=LMS))


async def test_the_ticket_leaves_the_browser_only_in_a_form_body_and_never_in_a_url(
    world: Any, make_user: Callable[..., User]
) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    grant = await ticket_for(browser, products["lms"], "ide", "/workspace/7?tab=1")
    landed = await deliver(products["ide"], grant["ticket"], origin=LMS)
    assert grant["ticket"] not in landed.headers["location"]
    assert grant["ticket"] not in grant["redeem_url"]
    assert urlsplit(grant["redeem_url"]).query == "" and urlsplit(grant["redeem_url"]).fragment == ""


# --------------------------------------------------------------------------- refusals


async def test_a_replayed_ticket_starts_no_second_session(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ticket = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    assert session_cookie(await deliver(products["ide"], ticket, origin=LMS))
    replay = await deliver(products["ide"], ticket, origin=LMS)
    assert replay.status_code == 400 and "set-cookie" not in replay.headers


async def test_a_ticket_for_one_service_is_useless_at_another(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member", "staging": "member"})
    ticket = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    elsewhere = await deliver(products["staging"], ticket, origin=LMS)
    assert elsewhere.status_code == 400 and "set-cookie" not in elsewhere.headers
    rightful = await deliver(products["ide"], ticket, origin=LMS)  # burned by the attempt
    assert rightful.status_code == 400 and "set-cookie" not in rightful.headers


@pytest.mark.parametrize("mangle", [lambda t: t[:-2] + "AA", lambda t: t[::-1], lambda t: "A" * 43, lambda t: ""])
async def test_a_tampered_ticket_is_refused(
    world: Any, make_user: Callable[..., User], mangle: Callable[[str], str]
) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ticket = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    refused = await deliver(products["ide"], mangle(ticket), origin=LMS)
    assert refused.status_code == 400 and "set-cookie" not in refused.headers


@pytest.mark.parametrize("origin", ["https://evil.example", STAGING, None])
async def test_a_ticket_posted_from_the_wrong_page_cannot_sign_a_victim_in(
    world: Any, make_user: Callable[..., User], origin: str | None
) -> None:
    """Login CSRF: an attacker's ticket must not log a victim's browser into the attacker's account."""
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ticket = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    refused = await deliver(products["ide"], ticket, origin=origin)
    assert refused.status_code == 403 and "set-cookie" not in refused.headers


async def test_an_expired_ticket_and_a_ended_central_session_are_refused(
    world: Any, make_user: Callable[..., User], owner_url: str
) -> None:
    import psycopg

    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    stale = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE identity.handoff_tickets SET expires_at = now() - interval '1 second'")
    assert (await deliver(products["ide"], stale, origin=LMS)).status_code == 400
    live = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    await browser.post("/auth/logout", headers=SAME_ORIGIN)
    assert (await deliver(products["ide"], live, origin=LMS)).status_code == 400


async def test_a_return_path_cannot_leave_the_destination(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    for asked in ("//evil.example/x", "https://evil.example", "/handoff/redeem"):
        grant = await ticket_for(browser, products["lms"], "ide", asked)
        landed = await deliver(products["ide"], grant["ticket"], origin=LMS)
        assert landed.headers["location"] == "/"


async def test_the_form_must_be_a_form(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ide = products["ide"]
    response = await ide.http.post("/handoff/redeem", json={"ticket": "x" * 43}, headers={"origin": LMS})
    assert response.status_code == 415
    response = await ide.http.post(
        "/handoff/redeem",
        content="ticket=a&ticket=b",
        headers={"content-type": "application/x-www-form-urlencoded", "origin": LMS},
    )
    assert response.status_code == 400
    assert (await ide.http.get("/handoff/redeem")).status_code == 405  # a link cannot redeem a ticket


async def test_an_unreachable_identity_service_leaves_nobody_half_signed_in(
    world: Any, make_user: Callable[..., User]
) -> None:
    browser, products, identity_app = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ticket = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    broken, _ = build_product("ide", IDE, identity_app, down=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=broken), base_url=IDE) as ide_down:
        response = await ide_down.post(
            "/handoff/redeem",
            content=f"ticket={ticket}",
            headers={"content-type": "application/x-www-form-urlencoded", "origin": LMS},
        )
    assert response.status_code == 503 and "set-cookie" not in response.headers


async def test_a_service_with_the_wrong_secret_gets_nothing(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, identity_app = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ticket = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    impostor, _ = build_product("ide", IDE, identity_app, secret="not-the-secret")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=impostor), base_url=IDE) as client:
        response = await client.post(
            "/handoff/redeem",
            content=f"ticket={ticket}",
            headers={"content-type": "application/x-www-form-urlencoded", "origin": LMS},
        )
    assert response.status_code == 503 and "set-cookie" not in response.headers
    assert session_cookie(
        await deliver(products["ide"], ticket, origin=LMS)
    )  # the ticket was not spent by the impostor


# --------------------------------------------------------------------------- isolation and authorisation


async def test_each_service_decides_for_itself_who_is_an_administrator(
    world: Any, make_user: Callable[..., User]
) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "admin", "ide": "member"})
    lms_cookie = session_cookie(
        await deliver(products["lms"], (await ticket_for(browser, products["ide"], "lms"))["ticket"], origin=IDE)
    )
    ide_cookie = session_cookie(
        await deliver(products["ide"], (await ticket_for(browser, products["lms"], "ide"))["ticket"], origin=LMS)
    )
    assert lms_cookie and ide_cookie
    assert (await open_service(products["lms"], lms_cookie, "/api/admin", "POST")).status_code == 200
    denied = await open_service(
        products["ide"], ide_cookie, "/api/admin", "POST"
    )  # admin in the LMS is nothing in the IDE
    assert (denied.status_code, denied.json()) == (403, {"detail": {"code": "admin_required"}})


async def test_a_person_the_destination_does_not_know_gets_no_session(
    world: Any, make_user: Callable[..., User]
) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member"})  # not provisioned in the IDE
    ticket = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
    response = await deliver(products["ide"], ticket, origin=LMS)
    assert response.status_code == 403 and "set-cookie" not in response.headers


async def test_one_services_session_is_worthless_at_another(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ide_cookie = session_cookie(
        await deliver(products["ide"], (await ticket_for(browser, products["lms"], "ide"))["ticket"], origin=LMS)
    )
    assert ide_cookie
    assert (await open_service(products["lms"], ide_cookie)).status_code == 401


async def test_a_session_cookie_cannot_be_driven_from_another_site(world: Any, make_user: Callable[..., User]) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ide = products["ide"]
    cookie = session_cookie(
        await deliver(ide, (await ticket_for(browser, products["lms"], "ide"))["ticket"], origin=LMS)
    )
    assert cookie
    cookies = {ide.cookie_name(): cookie}
    assert (await ide.http.post("/api/note", cookies=cookies)).status_code == 403  # no Origin
    assert (
        await ide.http.post("/api/note", cookies=cookies, headers={"origin": "https://evil.example"})
    ).status_code == 403
    assert (await ide.http.post("/api/note", cookies=cookies, headers={"origin": LMS})).status_code == 403  # a sibling
    assert (await ide.http.post("/api/note", cookies=cookies, headers={"origin": IDE})).status_code == 200
    assert (await ide.http.get("/api/me", cookies=cookies)).status_code == 200  # reads need no origin


async def test_an_invalid_bearer_header_is_not_rescued_by_a_valid_cookie(
    world: Any, make_user: Callable[..., User]
) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    ide = products["ide"]
    cookie = session_cookie(
        await deliver(ide, (await ticket_for(browser, products["lms"], "ide"))["ticket"], origin=LMS)
    )
    response = await ide.http.get(
        "/api/me", cookies={ide.cookie_name(): cookie or ""}, headers={"authorization": "Bearer junk"}
    )
    assert response.status_code == 401


# --------------------------------------------------------------------------- logout


async def test_local_logout_ends_one_services_session_and_nothing_else(
    world: Any, make_user: Callable[..., User]
) -> None:
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    cookie = session_cookie(
        await deliver(products["ide"], (await ticket_for(browser, products["lms"], "ide"))["ticket"], origin=LMS)
    )
    assert cookie
    ide = products["ide"]
    assert (await ide.http.post("/handoff/logout", headers={"origin": "https://evil.example"})).status_code == 403
    out = await ide.http.post("/handoff/logout", headers={"origin": IDE})
    assert out.status_code == 204 and "__Host-vf_session_ide=" in out.headers["set-cookie"]
    assert "max-age=0" in out.headers["set-cookie"].lower()
    assert (
        await browser.post("/auth/session/token", headers={"origin": LMS})
    ).status_code == 200  # central session lives


async def test_central_sign_out_stops_new_hand_offs_but_not_an_established_local_session(
    world: Any, make_user: Callable[..., User]
) -> None:
    """The honest limit: a service's own session lasts until it expires (VETFAB_SESSION_SECONDS)."""
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    cookie = session_cookie(
        await deliver(products["ide"], (await ticket_for(browser, products["lms"], "ide"))["ticket"], origin=LMS)
    )
    assert cookie
    await browser.post("/auth/logout", headers=SAME_ORIGIN)
    refused = await browser.post("/auth/handoff", json={"target": "ide"}, headers={"origin": LMS})
    assert refused.status_code == 401
    assert (await open_service(products["ide"], cookie)).status_code == 200


# --------------------------------------------------------------------------- secrecy


async def test_no_ticket_or_secret_appears_in_logs(
    world: Any, make_user: Callable[..., User], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    browser, products, _ = world
    await signed_in_person(browser, make_user, products, {"lms": "member", "ide": "member"})
    tickets = []
    for origin in (LMS, "https://evil.example"):
        ticket = (await ticket_for(browser, products["lms"], "ide"))["ticket"]
        tickets.append(ticket)
        await deliver(products["ide"], ticket, origin=origin)
    await deliver(products["ide"], tickets[0], origin=LMS)
    for secret in [*tickets, *SERVICE_SECRETS.values()]:
        assert secret not in caplog.text
