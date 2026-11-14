"""Account status changes requested by a product (CONTRACT.md, "Account status"): who may ask, what is refused, what
a change does (status, sessions, the audit record, the user feed) and that repeating it is harmless.
"""

import uuid
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import psycopg
import pytest
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from identity.store import User
from tests.conftest import ORIGIN, build_app, client_for
from tests.test_user_feed import basic, feed_settings, sha

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

# `lms` may read the feed and change status; `reports` may only read the feed; `old` and `waiting` are allowed both
# but are not active.
FEED = "lms,reports,old,waiting"
STATUS = "lms,old,waiting"


def path(user_id: UUID | str) -> str:
    return f"/auth/service/users/{user_id}/status"


def status_settings(login_url: str, keys_dir: Path, **overrides: Any) -> Any:
    values = {"user_feed_services": FEED, "account_status_services": STATUS, **overrides}
    return feed_settings(login_url, keys_dir, **values)


@pytest.fixture
def app(login_url: str, pool: AsyncConnectionPool, keys_dir: Path, owner_url: str) -> FastAPI:
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute(
            """INSERT INTO identity.services (id, display_name, environment, base_url, secret_sha256, status)
               VALUES ('waiting', 'Waiting', 'staging', 'https://waiting.vetfab.ai', %s, 'pending')""",
            (sha("waiting-secret"),),
        )
    built = build_app(status_settings(login_url, keys_dir), pool, keys_dir)
    assert isinstance(built, FastAPI)
    return built


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with client_for(app) as c:
        yield c


@pytest.fixture
def owner_conn(owner_url: str) -> Any:
    with psycopg.connect(owner_url, autocommit=True) as conn:
        yield conn


@pytest.fixture
def admin(make_user: Callable[..., User]) -> User:
    """The product administrator on whose behalf the product asks: an approved account here."""
    return make_user()


def status_of(conn: Any, user_id: UUID) -> str:
    return conn.execute("SELECT status FROM public.users WHERE id = %s", (user_id,)).fetchone()[0]


def audits(conn: Any, user_id: UUID) -> list[tuple[str, UUID | None, dict[str, Any]]]:
    return conn.execute(
        "SELECT action, actor_id, metadata FROM identity.audit WHERE user_id = %s ORDER BY id", (user_id,)
    ).fetchall()


def add_session(conn: Any, user_id: UUID) -> None:
    conn.execute(
        """INSERT INTO identity.refresh_tokens (token_hash, user_id, family_id, expires_at)
           VALUES (%s, %s, gen_random_uuid(), now() + interval '1 day')""",
        (uuid.uuid4().bytes * 2, user_id),
    )


def live_sessions(conn: Any, user_id: UUID) -> int:
    return conn.execute(
        "SELECT count(*) FROM identity.refresh_tokens WHERE user_id = %s AND revoked_at IS NULL", (user_id,)
    ).fetchone()[0]


async def ask(
    client: httpx.AsyncClient, user_id: UUID | str, body: Any, *, service: dict[str, str] | None = None
) -> httpx.Response:
    return await client.post(path(user_id), json=body, headers=service or basic("lms"))


# --------------------------------------------------------------------------- who may ask


@pytest.mark.parametrize(
    "authorization",
    [None, "Bearer abc", "Basic !!!not-base64", "Basic bG1zOndyb25nLXNlY3JldA=="],  # the last: lms:wrong-secret
)
async def test_bad_or_missing_credentials_are_401(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User], owner_conn: Any, authorization: str | None
) -> None:
    target = make_user(status="pending")
    headers = {"Authorization": authorization} if authorization else {}
    response = await client.post(
        path(target.id), json={"status": "approved", "actor_id": str(admin.id)}, headers=headers
    )
    assert response.status_code == 401
    assert response.json() == {"detail": {"code": "invalid_client"}}
    assert response.headers["www-authenticate"] == 'Basic realm="vetfab-identity"'
    assert response.headers["cache-control"] == "no-store"
    assert status_of(owner_conn, target.id) == "pending"


@pytest.mark.parametrize(
    "credentials",
    [
        basic("reports"),  # active and allowed the feed, which implies nothing here
        basic("ide"),  # active, allowed neither
        basic("old"),  # allowed, but disabled
        basic("waiting", "waiting-secret"),  # allowed, but still pending approval
    ],
)
async def test_a_service_without_the_permission_is_403(
    client: httpx.AsyncClient,
    admin: User,
    make_user: Callable[..., User],
    owner_conn: Any,
    credentials: dict[str, str],
) -> None:
    target = make_user(status="pending")
    response = await ask(client, target.id, {"status": "approved", "actor_id": str(admin.id)}, service=credentials)
    assert (response.status_code, response.json()) == (403, {"detail": {"code": "account_status_not_allowed"}})
    assert response.headers["cache-control"] == "no-store"
    assert status_of(owner_conn, target.id) == "pending"
    assert audits(owner_conn, target.id) == []


async def test_it_is_off_by_default_even_for_a_feed_reader(
    login_url: str,
    pool: AsyncConnectionPool,
    keys_dir: Path,
    admin: User,
    make_user: Callable[..., User],
    owner_conn: Any,
) -> None:
    target = make_user(status="pending")
    app = build_app(feed_settings(login_url, keys_dir), pool, keys_dir)  # the feed's allowlist only
    async with client_for(app) as c:
        assert (await c.get("/auth/service/users", headers=basic("lms"))).status_code == 200
        response = await ask(c, target.id, {"status": "approved", "actor_id": str(admin.id)})
    assert (response.status_code, response.json()) == (403, {"detail": {"code": "account_status_not_allowed"}})
    assert status_of(owner_conn, target.id) == "pending"


async def test_disabling_the_service_stops_it_at_once(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User], owner_conn: Any
) -> None:
    target = make_user(status="pending")
    body = {"status": "approved", "actor_id": str(admin.id)}
    assert (await ask(client, make_user(status="pending").id, body)).status_code == 200  # seeds the registry
    owner_conn.execute("UPDATE identity.services SET status = 'disabled' WHERE id = 'lms'")
    assert (await ask(client, target.id, body)).status_code == 403
    assert status_of(owner_conn, target.id) == "pending"


async def test_browsers_get_no_cors_answer(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User]
) -> None:
    target = make_user(status="pending")
    response = await client.post(
        path(target.id),
        json={"status": "approved", "actor_id": str(admin.id)},
        headers={**basic("lms"), "origin": ORIGIN},
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    preflight = await client.options(
        path(target.id), headers={"origin": ORIGIN, "access-control-request-method": "POST"}
    )
    assert "access-control-allow-origin" not in preflight.headers


# --------------------------------------------------------------------------- what a change does


async def test_approving_a_pending_account(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User], owner_conn: Any
) -> None:
    target = make_user(status="pending")
    add_session(owner_conn, target.id)  # a pending account may be signed in (it sees the waiting page)
    response = await ask(client, target.id, {"status": "approved", "actor_id": str(admin.id), "reason": " cohort 3 "})
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "user": {"id": str(target.id), "status": "approved"},
        "previous_status": "pending",
        "changed": True,
        "sessions_revoked": 0,
    }
    assert status_of(owner_conn, target.id) == "approved"
    assert live_sessions(owner_conn, target.id) == 1  # approval signs nobody out
    assert audits(owner_conn, target.id) == [
        (
            "status_change",
            admin.id,
            {
                "via": "service",
                "service": "lms",
                "from": "pending",
                "to": "approved",
                "reason": "cohort 3",
                "sessions_revoked": 0,
            },
        )
    ]


@pytest.mark.parametrize(("start", "wanted"), [("pending", "rejected"), ("approved", "suspended")])
async def test_rejecting_or_suspending_signs_the_account_out(
    client: httpx.AsyncClient,
    admin: User,
    make_user: Callable[..., User],
    owner_conn: Any,
    start: str,
    wanted: str,
) -> None:
    target = make_user(status=start)
    add_session(owner_conn, target.id)
    add_session(owner_conn, target.id)
    add_session(owner_conn, admin.id)
    response = await ask(client, target.id, {"status": wanted, "actor_id": str(admin.id)})
    assert response.status_code == 200, response.text
    assert response.json()["sessions_revoked"] == 2 and response.json()["changed"] is True
    assert status_of(owner_conn, target.id) == wanted
    assert live_sessions(owner_conn, target.id) == 0
    assert live_sessions(owner_conn, admin.id) == 1  # nobody else's
    reasons = owner_conn.execute(
        "SELECT DISTINCT revoked_reason FROM identity.refresh_tokens WHERE user_id = %s", (target.id,)
    ).fetchall()
    assert reasons == [("admin",)]  # the reason `identity-admin set-status` records
    ((action, actor_id, meta),) = audits(owner_conn, target.id)
    assert (action, actor_id) == ("status_change", admin.id)
    assert meta == {"via": "service", "service": "lms", "from": start, "to": wanted, "sessions_revoked": 2}


async def test_a_suspended_account_can_be_approved_again(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User], owner_conn: Any
) -> None:
    target = make_user(status="suspended")
    response = await ask(client, target.id, {"status": "approved", "actor_id": str(admin.id)})
    assert response.status_code == 200 and response.json()["previous_status"] == "suspended"
    assert status_of(owner_conn, target.id) == "approved"


async def test_the_change_reaches_the_user_feed(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User], owner_conn: Any
) -> None:
    """The product never writes its copy: the new status comes back to it as a feed event."""
    target = make_user(status="pending")
    before = owner_conn.execute("SELECT coalesce(max(seq), 0) FROM identity.user_events").fetchone()[0]
    assert (await ask(client, target.id, {"status": "approved", "actor_id": str(admin.id)})).status_code == 200
    events = owner_conn.execute(
        "SELECT type, status FROM identity.user_events WHERE seq > %s AND user_id = %s", (before, target.id)
    ).fetchall()
    assert events == [("user.updated", "approved")]


async def test_repeating_a_request_changes_nothing_more(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User], owner_conn: Any
) -> None:
    target = make_user(status="approved")
    add_session(owner_conn, target.id)
    body = {"status": "suspended", "actor_id": str(admin.id)}
    first = await ask(client, target.id, body)
    head = owner_conn.execute("SELECT coalesce(max(seq), 0) FROM identity.user_events").fetchone()[0]
    second = await ask(client, target.id, body)
    assert (first.status_code, second.status_code) == (200, 200)
    assert second.json() == {
        "user": {"id": str(target.id), "status": "suspended"},
        "previous_status": "suspended",
        "changed": False,
        "sessions_revoked": 0,
    }
    assert len(audits(owner_conn, target.id)) == 1  # one change, one record
    assert owner_conn.execute("SELECT coalesce(max(seq), 0) FROM identity.user_events").fetchone()[0] == head


async def test_a_repeat_still_signs_out_a_session_that_should_not_exist(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User], owner_conn: Any
) -> None:
    target = make_user(status="suspended")
    add_session(owner_conn, target.id)  # e.g. suspended by a direct write that revoked nothing
    response = await ask(client, target.id, {"status": "suspended", "actor_id": str(admin.id)})
    assert response.json()["changed"] is False and response.json()["sessions_revoked"] == 1
    assert live_sessions(owner_conn, target.id) == 0
    ((action, _, meta),) = audits(owner_conn, target.id)
    assert action == "status_change" and meta["from"] == meta["to"] == "suspended" and meta["sessions_revoked"] == 1


# --------------------------------------------------------------------------- what is refused


async def test_an_administrator_account_is_never_changed(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User], owner_conn: Any
) -> None:
    target = make_user()
    owner_conn.execute("UPDATE public.users SET role = 'admin' WHERE id = %s", (target.id,))
    add_session(owner_conn, target.id)
    response = await ask(client, target.id, {"status": "suspended", "actor_id": str(admin.id), "reason": "oops"})
    assert (response.status_code, response.json()) == (403, {"detail": {"code": "admin_account"}})
    assert status_of(owner_conn, target.id) == "approved"
    assert live_sessions(owner_conn, target.id) == 1
    assert audits(owner_conn, target.id) == [
        (
            "admin_denied",
            admin.id,
            {"via": "service", "service": "lms", "from": "approved", "to": "suspended", "reason": "oops"},
        )
    ]


async def test_a_bootstrap_administrator_email_is_never_changed(
    login_url: str,
    pool: AsyncConnectionPool,
    keys_dir: Path,
    admin: User,
    make_user: Callable[..., User],
    owner_conn: Any,
) -> None:
    """An IDENTITY_ADMIN_EMAILS account becomes an approved administrator at its next sign-in, whatever its row says."""
    target = make_user(status="pending")
    app = build_app(status_settings(login_url, keys_dir, admin_emails=target.email.upper()), pool, keys_dir)
    async with client_for(app) as c:
        response = await ask(c, target.id, {"status": "rejected", "actor_id": str(admin.id)})
    assert (response.status_code, response.json()) == (403, {"detail": {"code": "admin_account"}})
    assert status_of(owner_conn, target.id) == "pending"


@pytest.mark.parametrize("actor_status", ["pending", "rejected", "suspended"])
async def test_the_acting_person_must_be_an_approved_account(
    client: httpx.AsyncClient, make_user: Callable[..., User], owner_conn: Any, actor_status: str
) -> None:
    target, actor = make_user(status="pending"), make_user(status=actor_status)
    for actor_id in (actor.id, uuid.uuid4()):
        response = await ask(client, target.id, {"status": "approved", "actor_id": str(actor_id)})
        assert (response.status_code, response.json()) == (403, {"detail": {"code": "actor_not_allowed"}})
    assert status_of(owner_conn, target.id) == "pending"
    assert audits(owner_conn, target.id) == []


async def test_nobody_changes_their_own_account(client: httpx.AsyncClient, admin: User, owner_conn: Any) -> None:
    response = await ask(client, admin.id, {"status": "suspended", "actor_id": str(admin.id)})
    assert (response.status_code, response.json()) == (409, {"detail": {"code": "own_account"}})
    assert status_of(owner_conn, admin.id) == "approved"


async def test_an_unknown_account_is_404(client: httpx.AsyncClient, admin: User) -> None:
    response = await ask(client, uuid.uuid4(), {"status": "approved", "actor_id": str(admin.id)})
    assert (response.status_code, response.json()) == (404, {"detail": {"code": "user_not_found"}})


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ({"status": "approved", "actor_id": "ACTOR", "email": "x@example.com"}, "email"),
        ({"status": "approved", "actor_id": "ACTOR", "role": "admin"}, "role"),
        ({"status": "approved", "actor_id": "ACTOR", "password": "x"}, "password"),
        ({"status": "pending", "actor_id": "ACTOR"}, "status"),  # a reset is an operator's, not a product's
        ({"status": "deleted", "actor_id": "ACTOR"}, "status"),
        ({"status": ["approved"], "actor_id": "ACTOR"}, "status"),
        ({"actor_id": "ACTOR"}, "status"),
        ({"status": "approved"}, "actor_id"),
        ({"status": "approved", "actor_id": "not-a-uuid"}, "actor_id"),
        ({"status": "approved", "actor_id": 7}, "actor_id"),
        ({"status": "approved", "actor_id": "ACTOR", "reason": "x" * 501}, "reason"),
        ({"status": "approved", "actor_id": "ACTOR", "reason": 5}, "reason"),
        (["approved"], "body"),
    ],
)
async def test_a_malformed_request_is_422_and_changes_nothing(
    client: httpx.AsyncClient,
    admin: User,
    make_user: Callable[..., User],
    owner_conn: Any,
    body: Any,
    field: str,
) -> None:
    target = make_user(status="pending")
    if isinstance(body, dict):
        body = {k: (str(admin.id) if v == "ACTOR" else v) for k, v in body.items()}
    response = await ask(client, target.id, body)
    assert (response.status_code, response.json()) == (422, {"detail": {"code": "invalid_request", "field": field}})
    assert status_of(owner_conn, target.id) == "pending"


async def test_the_body_must_be_small_json(
    client: httpx.AsyncClient, admin: User, make_user: Callable[..., User]
) -> None:
    target = make_user(status="pending")
    for content, headers, field in (
        (b"status=approved", {"content-type": "application/x-www-form-urlencoded"}, "content-type"),
        (b"{not json", {"content-type": "application/json"}, "body"),
        (b'{"status": "approved", "pad": "' + b"x" * 2100 + b'"}', {"content-type": "application/json"}, "body"),
    ):
        response = await client.post(path(target.id), content=content, headers={**basic("lms"), **headers})
        assert (response.status_code, response.json()["detail"]) == (422, {"code": "invalid_request", "field": field})
    response = await ask(client, "not-a-uuid", {"status": "approved", "actor_id": str(admin.id)})
    assert response.json() == {"detail": {"code": "invalid_request", "field": "id"}}


async def test_requests_are_rate_limited_per_service_apart_from_the_feed(
    login_url: str,
    pool: AsyncConnectionPool,
    keys_dir: Path,
    admin: User,
    make_user: Callable[..., User],
    owner_conn: Any,
) -> None:
    app = build_app(status_settings(login_url, keys_dir, account_status_rate_limit=2), pool, keys_dir)
    body = {"status": "approved", "actor_id": str(admin.id)}
    async with client_for(app) as c:
        for _ in range(2):
            assert (await ask(c, make_user(status="pending").id, body)).status_code == 200
        target = make_user(status="pending")
        limited = await ask(c, target.id, body)
        assert (limited.status_code, limited.json()) == (429, {"detail": {"code": "too_many_requests"}})
        assert 1 <= int(limited.headers["retry-after"]) <= 600
        assert status_of(owner_conn, target.id) == "pending"
        assert (await c.get("/auth/service/users", headers=basic("lms"))).status_code == 200  # its own counter
