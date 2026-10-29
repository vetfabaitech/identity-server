"""The developer portal API: roles, ownership, validation, secrets, CSRF, persistence and consistency between instances.

Real identity service (in-process) on the throwaway Postgres. People are real accounts signed in through the real sign-in
form, so the portal's authentication is the identity service's own and nothing here fakes who is calling.
"""

import hashlib
import inspect
import json
import logging
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
from tests.conftest import ORIGIN, PASSWORD, SAME_ORIGIN, build_app, client_for, make_settings

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

API = "/auth/admin"
LMS_SECRET = "lms-bootstrap-secret"
IDE_URL = "https://ide.vetfab.ai"
NEW_URL = "https://newsvc.vetfab.ai"


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


SEED = json.dumps(
    {
        "services": [
            {"id": "lms", "display_name": "Vetfab LMS", "base_url": ORIGIN, "secret_sha256": sha(LMS_SECRET)},
            {
                "id": "ide",
                "display_name": "Vetfab IDE",
                "base_url": IDE_URL,
                "secret_sha256": sha("ide-bootstrap-secret"),
            },
        ]
    }
)


def make_app(login_url: str, pool: AsyncConnectionPool[Any], keys_dir: Path, **overrides: Any) -> FastAPI:
    settings = make_settings(login_url, keys_dir, app_origins=f"{ORIGIN},{IDE_URL}", services=SEED, **overrides)
    return build_app(settings, pool, keys_dir)  # type: ignore[return-value]


@pytest.fixture
def app(login_url: str, pool: AsyncConnectionPool[Any], keys_dir: Path) -> FastAPI:
    return make_app(login_url, pool, keys_dir)


@pytest.fixture
def set_role(owner_url: str) -> Callable[[User, str], None]:
    def run(user: User, role: str) -> None:
        with psycopg.connect(owner_url, autocommit=True) as conn:
            conn.execute("UPDATE public.users SET role = %s WHERE id = %s", (role, user.id))

    return run


@pytest.fixture
def person(make_user: Callable[..., User], app: FastAPI) -> Callable[..., Any]:
    """Signs a new account in (a browser of its own) and returns (client, user)."""

    async def make(*, admin: bool = False, environments: list[str] | None = None, set_role_fn: Any = None) -> Any:
        user = make_user(password=PASSWORD)
        client = client_for(app)
        response = await client.post(
            "/auth/login",
            data={"email": user.email, "password": PASSWORD, "redirect": "/", "state": "s"},
            headers=SAME_ORIGIN,
        )
        assert response.status_code == 303
        return client, user

    return make


@pytest.fixture
async def admin(
    person: Callable[..., Any], set_role: Callable[[User, str], None]
) -> AsyncIterator[tuple[httpx.AsyncClient, User]]:
    client, user = await person()
    set_role(user, "admin")
    yield client, user
    await client.aclose()


async def grant(admin_client: httpx.AsyncClient, user: User, environments: list[str]) -> None:
    response = await send(admin_client, "PUT", "/developers", {"email": user.email, "environments": environments})
    assert response.status_code == 200, response.text


async def send(
    client: httpx.AsyncClient, method: str, path: str, body: Any = None, *, origin: str | None = ORIGIN, **headers: str
) -> httpx.Response:
    request_headers = dict(headers)
    if origin is not None and method != "GET":
        request_headers["origin"] = origin
    kwargs: dict[str, Any] = {"headers": request_headers}
    if body is not None:
        kwargs["json"] = body
    return await client.request(method, f"{API}{path}", **kwargs)


def draft(**overrides: Any) -> dict[str, Any]:
    return {
        "id": "newsvc",
        "display_name": "New Service",
        "description": "A hypothetical service",
        "owner_team": "Platform",
        "environment": "staging",
        "base_url": NEW_URL,
        **overrides,
    }


async def register(client: httpx.AsyncClient, **overrides: Any) -> httpx.Response:
    return await send(client, "POST", "/services", draft(**overrides))


def rows(owner_url: str, query: str, *params: Any) -> list[tuple[Any, ...]]:
    with psycopg.connect(owner_url, autocommit=True) as conn:
        return conn.execute(query, params).fetchall()  # type: ignore[arg-type]


# --------------------------------------------------------------------------- who may use the portal


async def test_no_session_means_sign_in(app: FastAPI) -> None:
    async with client_for(app) as anonymous:
        response = await anonymous.get(f"{API}/me")
    assert (response.status_code, response.json()) == (401, {"error": "not_signed_in"})


async def test_an_ordinary_account_is_not_authorised_and_the_attempt_is_audited(
    person: Callable[..., Any], owner_url: str
) -> None:
    client, user = await person()
    assert (await send(client, "GET", "/me")).status_code == 403
    assert (await send(client, "GET", "/services")).json() == {"error": "not_authorised"}
    attempt = await register(client)
    assert (attempt.status_code, attempt.json()) == (403, {"error": "not_authorised"})
    audited = rows(
        owner_url,
        "SELECT metadata->>'path' FROM identity.audit WHERE action = 'admin_denied' AND user_id = %s",
        user.id,
    )
    assert audited == [("/auth/admin/services",)]  # the refused change is recorded; refused reads are not
    assert rows(owner_url, "SELECT count(*) FROM identity.services WHERE id = 'newsvc'") == [(0,)]


async def test_an_administrator_and_a_developer_see_what_they_may_do(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any]
) -> None:
    admin_client, _ = admin
    body = (await send(admin_client, "GET", "/me")).json()
    assert body["is_admin"] and body["register_environments"] == ["local", "staging", "production"]
    client, user = await person()
    await grant(admin_client, user, ["staging"])
    body = (await send(client, "GET", "/me")).json()
    assert not body["is_admin"] and body["register_environments"] == ["staging"]


# --------------------------------------------------------------------------- registering


async def test_registration_creates_a_pending_service_and_shows_the_secret_once(
    admin: tuple[httpx.AsyncClient, User], owner_url: str
) -> None:
    client, user = admin
    response = await register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["secret_shown_once"] and len(body["secret"]) >= 40
    service = body["service"]
    assert (service["status"], service["owner"], service["source"]) == ("pending", user.email, "managed")
    assert service["permissions"]["enable"] is True
    assert body["secret"] not in json.dumps(service) and "sha256" not in json.dumps(service)
    stored = rows(owner_url, "SELECT secret_sha256, status, owner_user_id FROM identity.services WHERE id = 'newsvc'")
    assert stored == [(sha(body["secret"]), "pending", user.id)]  # only the hash is stored
    assert body["secret"] not in json.dumps(rows(owner_url, "SELECT row_to_json(s)::text FROM identity.services s"))
    again = (await send(client, "GET", "/services/newsvc")).json()
    assert "secret" not in again and body["secret"] not in json.dumps(again)  # never returned again


async def test_a_production_registration_is_not_activated_automatically(admin: tuple[httpx.AsyncClient, User]) -> None:
    client, _ = admin
    body = (await register(client, environment="production")).json()
    assert body["service"]["status"] == "pending"
    assert (await client.get("/auth/services", headers={"origin": ORIGIN})).json()["services"][0]["id"] == "lms"
    assert "newsvc" not in [
        s["id"] for s in (await client.get("/auth/services", headers={"origin": ORIGIN})).json()["services"]
    ]


async def test_developers_register_only_where_granted_and_never_production(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any]
) -> None:
    admin_client, _ = admin
    dev, user = await person()
    assert (await register(dev)).status_code == 403  # no grant yet
    await grant(admin_client, user, ["staging"])
    assert (await register(dev)).status_code == 201
    for environment in ("production", "local"):
        refused = await register(dev, id="other", base_url="https://other.vetfab.ai", environment=environment)
        assert (refused.status_code, refused.json()["error"]) == (403, "environment_not_permitted")


async def test_a_developer_cannot_grant_themselves_anything(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any]
) -> None:
    admin_client, _ = admin
    dev, user = await person()
    await grant(admin_client, user, ["staging"])
    for method, path, body in (
        ("PUT", "/developers", {"email": user.email, "environments": ["local", "staging"]}),
        ("GET", "/developers", None),
        ("DELETE", f"/developers/{user.id}", None),
    ):
        response = await send(dev, method, path, body)
        assert (response.status_code, response.json()) == (403, {"error": "administrator_only"})
    assert (
        await send(admin_client, "PUT", "/developers", {"email": user.email, "environments": ["production"]})
    ).status_code == 400


@pytest.mark.parametrize("field", ["owner", "owner_user_id", "status", "secret_sha256", "role", "source", "created_by"])
async def test_owner_status_and_credentials_are_never_taken_from_the_request(
    admin: tuple[httpx.AsyncClient, User], owner_url: str, field: str
) -> None:
    client, _ = admin
    response = await register(client, **{field: "attacker"})
    assert (response.status_code, response.json()["error"]) == (400, "unknown_field")
    assert rows(owner_url, "SELECT count(*) FROM identity.services WHERE id = 'newsvc'") == [(0,)]


@pytest.mark.parametrize(
    "overrides",
    [
        {"base_url": "javascript:alert(1)"},
        {"base_url": "https://user:pw@newsvc.vetfab.ai"},
        {"base_url": "https://newsvc.vetfab.ai/app"},
        {"base_url": "https://newsvc.vetfab.ai?x=1"},
        {"base_url": "ftp://newsvc.vetfab.ai"},
        {"base_url": "newsvc.vetfab.ai"},
        {"base_url": "http://newsvc.vetfab.ai"},  # a deployed identity service refuses plain http
        {"environment": "production", "base_url": "https://localhost"},
        {"environment": "production", "base_url": "https://10.0.0.5"},
        {"id": "X"},
        {"id": "a"},
        {"id": "../etc"},
        {"callback_path": "//evil.example"},
        {"callback_path": "/a/../b"},
        {"callback_path": "https://evil.example/x"},
        {"session_seconds": 5},
        {"session_seconds": 99999},
        {"session_seconds": "900"},
        {"roles": ["root"]},
        {"return_path_prefixes": ["no-slash"]},
        {"display_name": ""},
        {"display_name": "x" * 61},
        {"environment": "dev"},
        {"base_url": "https://test.vetfab.ai"},  # the identity host itself
        {"base_url": IDE_URL},  # already registered to another service
        {"id": "lms"},  # already taken
    ],
)
async def test_unsafe_or_conflicting_configuration_is_rejected(
    admin: tuple[httpx.AsyncClient, User], owner_url: str, overrides: dict[str, Any]
) -> None:
    client, _ = admin
    response = await register(client, **overrides)
    assert response.status_code in (403, 422), response.text
    assert rows(owner_url, "SELECT count(*) FROM identity.services WHERE id = 'newsvc'") == [(0,)]


async def test_validation_reports_every_problem_without_contacting_the_address(
    admin: tuple[httpx.AsyncClient, User], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = admin

    def forbidden(*args: Any, **kwargs: Any) -> None:  # any outbound connection would be an SSRF vector
        raise AssertionError("validation must not make network requests")

    from identity.web import admin_routes

    source = inspect.getsource(admin_routes)
    assert not any(f"import {lib}" in source for lib in ("httpx", "requests", "urllib.request", "socket", "aiohttp"))
    monkeypatch.setattr("socket.socket.connect", forbidden)
    good = (await send(client, "POST", "/services/validate", draft(base_url="https://169.254.169.254"))).json()
    assert good["ok"] and any(c["code"] == "ip_host" for c in good["checks"])
    assert any(c["code"] == "no_network" for c in good["checks"])
    bad = (await send(client, "POST", "/services/validate", draft(id="lms", base_url="javascript:x"))).json()
    assert not bad["ok"]


async def test_a_ready_made_service_for_a_taken_origin_is_a_conflict(admin: tuple[httpx.AsyncClient, User]) -> None:
    client, _ = admin
    assert (await register(client)).status_code == 201
    second = await register(client, id="second")
    assert second.status_code == 422 and any(c["code"] == "origin_taken" for c in second.json()["checks"])


# --------------------------------------------------------------------------- ownership


async def test_developers_cannot_see_or_touch_each_others_services(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any]
) -> None:
    admin_client, _ = admin
    alice, a = await person()
    bob, b = await person()
    await grant(admin_client, a, ["staging"])
    await grant(admin_client, b, ["staging"])
    assert (await register(alice)).status_code == 201
    assert [s["id"] for s in (await send(alice, "GET", "/services")).json()["items"]] == ["newsvc"]
    assert (await send(bob, "GET", "/services")).json()["items"] == []
    for method, path, body in (
        ("GET", "/services/newsvc", None),
        ("GET", "/services/newsvc/activity", None),
        ("GET", "/services/newsvc/integration-config", None),
        ("PATCH", "/services/newsvc", {"description": "mine now"}),
        ("POST", "/services/newsvc/disable", {}),
        ("POST", "/services/newsvc/validate", {}),
        ("POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc"}),
    ):
        response = await send(bob, method, path, body)
        assert (response.status_code, response.json()) == (404, {"error": "not_found"}), (method, path)
    assert (await send(bob, "GET", "/services/does-not-exist")).status_code == 404  # same answer: no probing
    assert len((await send(admin_client, "GET", "/services")).json()["items"]) == 3  # lms, ide, newsvc


# --------------------------------------------------------------------------- editing


async def test_owners_edit_metadata_but_not_the_address_of_an_approved_service(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any]
) -> None:
    admin_client, _ = admin
    dev, user = await person()
    await grant(admin_client, user, ["staging"])
    assert (await register(dev)).status_code == 201
    ok = await send(
        dev, "PATCH", "/services/newsvc", {"description": "updated", "owner_team": "Infra", "session_seconds": 600}
    )
    assert ok.status_code == 200 and ok.json()["service"]["description"] == "updated"
    moved = await send(dev, "PATCH", "/services/newsvc", {"base_url": "https://moved.vetfab.ai"})  # still pending: fine
    assert moved.status_code == 200 and moved.json()["service"]["base_url"] == "https://moved.vetfab.ai"
    assert (await send(admin_client, "POST", "/services/newsvc/enable", {})).status_code == 200
    locked = await send(dev, "PATCH", "/services/newsvc", {"base_url": "https://evil.example"})
    assert (locked.status_code, locked.json()["error"]) == (403, "trusted_fields_locked")
    assert (await send(dev, "PATCH", "/services/newsvc", {"environment": "production"})).status_code == 403
    assert (await send(dev, "PATCH", "/services/newsvc", {"description": "still fine"})).status_code == 200


async def test_an_administrator_moving_an_active_service_must_confirm_and_cancels_its_tickets(
    admin: tuple[httpx.AsyncClient, User], owner_url: str
) -> None:
    client, _ = admin
    assert (await register(client)).status_code == 201
    assert (await send(client, "POST", "/services/newsvc/enable", {})).status_code == 200
    unconfirmed = await send(client, "PATCH", "/services/newsvc", {"base_url": "https://moved.vetfab.ai"})
    assert (unconfirmed.status_code, unconfirmed.json()["error"]) == (400, "confirmation_required")
    moved = await send(
        client, "PATCH", "/services/newsvc", {"base_url": "https://moved.vetfab.ai", "confirm": "newsvc"}
    )
    assert moved.status_code == 200
    assert rows(owner_url, "SELECT base_url FROM identity.services WHERE id = 'newsvc'") == [
        ("https://moved.vetfab.ai",)
    ]


@pytest.mark.parametrize(
    "body", [{}, {"unknown": 1}, {"id": "renamed"}, {"base_url": "javascript:x"}, {"roles": ["root"]}]
)
async def test_bad_edits_change_nothing(
    admin: tuple[httpx.AsyncClient, User], owner_url: str, body: dict[str, Any]
) -> None:
    client, _ = admin
    await register(client)
    response = await send(client, "PATCH", "/services/newsvc", body)
    assert response.status_code in (400, 422)
    assert rows(owner_url, "SELECT id, base_url FROM identity.services WHERE id = 'newsvc'") == [("newsvc", NEW_URL)]


# --------------------------------------------------------------------------- enabling and disabling


async def test_only_an_administrator_activates(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any]
) -> None:
    admin_client, _ = admin
    dev, user = await person()
    await grant(admin_client, user, ["staging"])
    await register(dev)
    refused = await send(dev, "POST", "/services/newsvc/enable", {})
    assert (refused.status_code, refused.json()) == (403, {"error": "administrator_only"})
    assert (await send(admin_client, "POST", "/services/newsvc/enable", {})).json()["service"]["status"] == "active"
    assert (await send(admin_client, "POST", "/services/newsvc/enable", {})).status_code == 409


async def test_a_production_service_needs_its_id_typed_to_activate_or_disable(
    admin: tuple[httpx.AsyncClient, User],
) -> None:
    client, _ = admin
    await register(client, environment="production")
    for action in ("enable", "disable"):
        refused = await send(client, "POST", f"/services/newsvc/{action}", {})
        assert (refused.status_code, refused.json()["error"]) == (400, "confirmation_required")
        wrong = await send(client, "POST", f"/services/newsvc/{action}", {"confirm": "nope"})
        assert wrong.status_code == 400
        if action == "enable":
            assert (await send(client, "POST", "/services/newsvc/enable", {"confirm": "newsvc"})).status_code == 200


async def test_an_active_service_joins_the_switcher_and_the_sign_in_allowlist_and_a_disabled_one_leaves(
    admin: tuple[httpx.AsyncClient, User], app: FastAPI
) -> None:
    client, _ = admin
    await register(client)
    cache = app.state.registry_cache
    preflight = lambda: client.options("/auth/handoff", headers={"origin": NEW_URL})  # noqa: E731
    assert (await preflight()).status_code == 403  # pending: not trusted with anything
    assert NEW_URL not in app.state.settings.app_origin_list
    await send(client, "POST", "/services/newsvc/enable", {})
    assert NEW_URL in app.state.settings.app_origin_list and (await preflight()).status_code == 204
    listed = (await client.get("/auth/services", headers={"origin": ORIGIN})).json()["services"]
    assert "newsvc" in [s["id"] for s in listed]
    csp = (await client.get("/auth/health")).headers["content-security-policy"]
    assert NEW_URL in csp  # form-action: a sign-in may be sent there now
    await send(client, "POST", "/services/newsvc/disable", {})
    assert NEW_URL not in app.state.settings.app_origin_list and (await preflight()).status_code == 403
    assert "newsvc" not in [
        s["id"] for s in (await client.get("/auth/services", headers={"origin": ORIGIN})).json()["services"]
    ]
    assert cache.registry.get("newsvc") is None


async def test_a_developer_can_disable_their_own_service_but_not_bring_it_back(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any]
) -> None:
    admin_client, _ = admin
    dev, user = await person()
    await grant(admin_client, user, ["staging"])
    await register(dev)
    await send(admin_client, "POST", "/services/newsvc/enable", {})
    assert (await send(dev, "POST", "/services/newsvc/disable", {})).json()["service"]["status"] == "disabled"
    assert (await send(dev, "POST", "/services/newsvc/enable", {})).status_code == 403
    assert (await send(dev, "POST", "/services/newsvc/disable", {})).status_code == 409


async def test_disabling_never_removes_the_service_or_any_account(
    admin: tuple[httpx.AsyncClient, User], owner_url: str
) -> None:
    client, user = admin
    await register(client)
    users_before = rows(owner_url, "SELECT count(*) FROM public.users")
    await send(client, "POST", "/services/newsvc/disable", {})
    assert rows(owner_url, "SELECT status FROM identity.services WHERE id = 'newsvc'") == [("disabled",)]
    assert rows(owner_url, "SELECT count(*) FROM public.users") == users_before
    with psycopg.connect(owner_url, autocommit=True) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("SET ROLE identity_app")
        conn.execute("DELETE FROM identity.services WHERE id = 'newsvc'")  # the service role cannot delete a service


# --------------------------------------------------------------------------- secrets


async def test_rotating_gives_a_new_secret_and_keeps_the_old_one_for_the_grace_window(
    admin: tuple[httpx.AsyncClient, User], app: FastAPI, owner_url: str
) -> None:
    from identity import registry_store

    client, _ = admin
    first = (await register(client)).json()["secret"]
    await send(client, "POST", "/services/newsvc/enable", {})
    refused = await send(client, "POST", "/services/newsvc/rotate-secret", {})
    assert (refused.status_code, refused.json()["error"]) == (400, "confirmation_required")
    rotated = (await send(client, "POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc"})).json()
    second = rotated["secret"]
    assert second != first and rotated["previous_valid_seconds"] == 3600 and rotated["secret_shown_once"]
    async with app.state.pool.connection() as conn:
        registry = await registry_store.load_registry(conn)
    assert registry.authenticate("newsvc", second) and registry.authenticate("newsvc", first)  # both inside the window
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE identity.services SET previous_secret_expires_at = now() - interval '1 second'")
    async with app.state.pool.connection() as conn:
        registry = await registry_store.load_registry(conn)
    assert registry.authenticate("newsvc", second) and registry.authenticate("newsvc", first) is None  # grace over
    assert "secret" not in (await send(client, "GET", "/services/newsvc")).json()["service"]


async def test_revoking_immediately_stops_the_old_secret_at_once(
    admin: tuple[httpx.AsyncClient, User], app: FastAPI
) -> None:
    from identity import registry_store

    client, _ = admin
    first = (await register(client)).json()["secret"]
    second = (
        await send(client, "POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc", "revoke_old": True})
    ).json()
    assert second["previous_valid_seconds"] == 0
    async with app.state.pool.connection() as conn:
        registry = await registry_store.load_registry(conn)
    # (a pending service never authenticates; activate to see the credential rules apply)
    await send(client, "POST", "/services/newsvc/enable", {})
    async with app.state.pool.connection() as conn:
        registry = await registry_store.load_registry(conn)
    assert registry.authenticate("newsvc", second["secret"]) and registry.authenticate("newsvc", first) is None


async def test_the_previous_secret_can_be_revoked_early(admin: tuple[httpx.AsyncClient, User], app: FastAPI) -> None:
    from identity import registry_store

    client, _ = admin
    first = (await register(client)).json()["secret"]
    await send(client, "POST", "/services/newsvc/enable", {})
    await send(client, "POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc"})
    assert (await send(client, "POST", "/services/newsvc/revoke-previous-secret", {})).status_code == 400  # confirm
    assert (
        await send(client, "POST", "/services/newsvc/revoke-previous-secret", {"confirm": "newsvc"})
    ).status_code == 200
    async with app.state.pool.connection() as conn:
        assert (await registry_store.load_registry(conn)).authenticate("newsvc", first) is None


async def test_secret_operations_are_rate_limited_and_secrets_stay_out_of_logs_and_audit(
    login_url: str,
    pool: AsyncConnectionPool[Any],
    keys_dir: Path,
    make_user: Callable[..., User],
    set_role: Callable[[User, str], None],
    owner_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    app = make_app(login_url, pool, keys_dir, admin_rate_limit=12)  # secret operations get a sixth: two
    user = make_user(password=PASSWORD)
    set_role(user, "admin")
    async with client_for(app) as client:
        await client.post(
            "/auth/login",
            data={"email": user.email, "password": PASSWORD, "redirect": "/", "state": "s"},
            headers=SAME_ORIGIN,
        )
        secret = (await register(client)).json()["secret"]
        rotated = (await send(client, "POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc"})).json()["secret"]
        limited = await send(client, "POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc"})
    assert (limited.status_code, limited.json()["error"]) == (429, "too_many_requests")
    haystack = caplog.text + json.dumps(rows(owner_url, "SELECT metadata::text FROM identity.audit"))
    assert secret not in haystack and rotated not in haystack and sha(secret) not in haystack


# --------------------------------------------------------------------------- CSRF and request hygiene


@pytest.mark.parametrize(
    "headers",
    [
        {"origin": None},
        {"origin": "https://evil.example"},
        {"origin": "null"},
        {"origin": ORIGIN, "sec-fetch-site": "cross-site"},
        {"origin": ORIGIN, "sec-fetch-site": "same-site"},
    ],
)
async def test_state_changing_calls_must_come_from_the_portals_own_page(
    admin: tuple[httpx.AsyncClient, User], owner_url: str, headers: dict[str, str | None]
) -> None:
    client, _ = admin
    origin = headers.get("origin")
    extra = {k: v for k, v in headers.items() if k != "origin" and v is not None}
    response = await send(client, "POST", "/services", draft(), origin=origin, **extra)
    assert (response.status_code, response.json()["error"]) == (403, "csrf")
    assert rows(owner_url, "SELECT count(*) FROM identity.services WHERE id = 'newsvc'") == [(0,)]


async def test_the_body_must_be_json(admin: tuple[httpx.AsyncClient, User]) -> None:
    client, _ = admin
    response = await client.post(
        f"{API}/services", content="id=x", headers={"origin": ORIGIN, "content-type": "text/plain"}
    )
    assert response.status_code == 415


async def test_reads_carry_no_cors_so_other_sites_cannot_read_them(admin: tuple[httpx.AsyncClient, User]) -> None:
    client, _ = admin
    response = await client.get(f"{API}/services", headers={"origin": "https://evil.example"})
    assert "access-control-allow-origin" not in response.headers


# --------------------------------------------------------------------------- the list


async def test_the_list_filters_searches_and_pages(admin: tuple[httpx.AsyncClient, User]) -> None:
    client, _ = admin
    for index in range(3):
        await register(
            client, id=f"extra-{index}", display_name=f"Extra {index}", base_url=f"https://extra{index}.vetfab.ai"
        )
    everything = (await send(client, "GET", "/services?page_size=2&page=2")).json()
    assert (everything["total"], everything["page"], everything["page_size"], len(everything["items"])) == (5, 2, 2, 2)
    assert everything["counts"] == {"pending": 3, "active": 2, "disabled": 0}
    assert (await send(client, "GET", "/services?status=pending")).json()["total"] == 3
    assert (await send(client, "GET", "/services?environment=production")).json()["total"] == 2  # the seeded two
    assert [s["id"] for s in (await send(client, "GET", "/services?q=extra%201")).json()["items"]] == ["extra-1"]
    assert (await send(client, "GET", "/services?q=zzz")).json()["items"] == []
    assert (await send(client, "GET", "/services?page_size=100000")).json()["page_size"] == 100


# --------------------------------------------------------------------------- generated configuration


async def test_integration_config_uses_the_real_keys_and_never_a_secret(
    admin: tuple[httpx.AsyncClient, User], owner_url: str
) -> None:
    client, _ = admin
    secret = (await register(client)).json()["secret"]
    config = (await send(client, "GET", "/services/newsvc/integration-config")).json()
    variables = {v["key"]: v for v in config["variables"]}
    assert variables["VETFAB_AUTH_URL"]["value"] == ORIGIN
    assert variables["VETFAB_ENVIRONMENT"]["value"] == "staging"
    assert variables["VETFAB_SERVICE_ID"]["value"] == "newsvc"
    assert variables["VETFAB_APP_URL"]["value"] == NEW_URL
    assert variables["VETFAB_SESSION_SECONDS"]["value"] == "900"
    assert (
        variables["VETFAB_SERVICE_SECRET"]["value"] is None and variables["VETFAB_SERVICE_SECRET"]["origin"] == "secret"
    )
    assert (
        variables["VETFAB_SESSION_SECRET"]["value"] is None
        and variables["VETFAB_SESSION_SECRET"]["origin"] == "generate"
    )
    assert secret not in json.dumps(config) and sha(secret) not in json.dumps(config)
    assert config["production_ready"] is False
    assert {r["id"]: r["state"] for r in config["readiness"]}["approved"] == "todo"
    assert (
        "vetfab-identity-adapter" in config["backend"]["package"]
        and "@vetfab/identity-adapter" == config["frontend"]["package"]
    )


async def test_a_registered_service_is_never_reported_production_ready(admin: tuple[httpx.AsyncClient, User]) -> None:
    client, _ = admin
    await register(client, environment="production")
    await send(client, "POST", "/services/newsvc/enable", {"confirm": "newsvc"})
    config = (await send(client, "GET", "/services/newsvc/integration-config")).json()
    states = {r["id"]: r["state"] for r in config["readiness"]}
    assert states["approved"] == "done" and states["https"] == "done" and states["browser"] == "manual"
    assert config["production_ready"] is False


# --------------------------------------------------------------------------- persistence and consistency


async def test_registrations_survive_a_restart_and_the_seed_never_overwrites_them(
    login_url: str,
    pool: AsyncConnectionPool[Any],
    keys_dir: Path,
    admin: tuple[httpx.AsyncClient, User],
    owner_url: str,
) -> None:
    client, user = admin
    await register(client)
    await send(
        client,
        "PATCH",
        "/services/ide",
        {"description": "edited in the portal", "base_url": "https://ide2.vetfab.ai", "confirm": "ide"},
    )
    rotated = (
        await send(client, "POST", "/services/lms/rotate-secret", {"confirm": "lms", "revoke_old": True})
    ).json()["secret"]
    restarted = make_app(login_url, pool, keys_dir)  # a new process: new cache, same environment seed
    async with client_for(restarted) as same_browser:
        same_browser.cookies = client.cookies
        listing = (await send(same_browser, "GET", "/services")).json()
    by_id = {s["id"]: s for s in listing["items"]}
    assert set(by_id) == {"lms", "ide", "newsvc"}
    assert by_id["ide"]["description"] == "edited in the portal" and by_id["ide"]["source"] == "bootstrap"
    assert rows(owner_url, "SELECT secret_sha256 FROM identity.services WHERE id = 'lms'") == [
        (sha(rotated),)
    ]  # not LMS_SECRET


async def test_environment_seed_is_inserted_once_and_marked_as_seeded(
    app: FastAPI, admin: tuple[httpx.AsyncClient, User], owner_url: str
) -> None:
    client, _ = admin
    items = (await send(client, "GET", "/services")).json()["items"]
    assert {s["id"]: (s["source"], s["status"]) for s in items} == {
        "lms": ("bootstrap", "active"),
        "ide": ("bootstrap", "active"),
    }
    events = rows(
        owner_url, "SELECT metadata->>'service' FROM identity.audit WHERE action = 'service_bootstrapped' ORDER BY id"
    )
    assert sorted(e[0] for e in events[-2:]) == ["ide", "lms"]  # (audit rows of earlier tests stay in the database)
    await app.state.registry_cache.refresh(app.state.pool)
    assert (
        rows(
            owner_url,
            "SELECT metadata->>'service' FROM identity.audit WHERE action = 'service_bootstrapped' ORDER BY id",
        )
        == events
    )


async def test_a_second_instance_sees_a_change_made_on_the_first(
    login_url: str, pool: AsyncConnectionPool[Any], keys_dir: Path, app: FastAPI, admin: tuple[httpx.AsyncClient, User]
) -> None:
    client, _ = admin
    other = make_app(login_url, pool, keys_dir, registry_refresh_seconds=0)
    await register(client)
    await send(client, "POST", "/services/newsvc/enable", {})
    async with client_for(other) as second:
        second.cookies = client.cookies
        # The switcher list reads the database: current at once on any instance.
        listed = (await second.get("/auth/services", headers={"origin": ORIGIN})).json()["services"]
        assert "newsvc" in [s["id"] for s in listed]
        assert (
            await second.options("/auth/handoff", headers={"origin": NEW_URL})
        ).status_code == 204  # refresh interval 0
        await send(client, "POST", "/services/newsvc/disable", {})
        assert "newsvc" not in [
            s["id"] for s in (await second.get("/auth/services", headers={"origin": ORIGIN})).json()["services"]
        ]


async def test_portal_changes_leave_the_seeded_services_alone(
    admin: tuple[httpx.AsyncClient, User], owner_url: str
) -> None:
    client, _ = admin
    before = rows(
        owner_url, "SELECT id, base_url, secret_sha256, status, updated_at FROM identity.services ORDER BY id"
    )
    await register(client)
    await send(client, "POST", "/services/newsvc/enable", {})
    await send(client, "POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc"})
    await send(client, "POST", "/services/newsvc/disable", {})
    after = rows(
        owner_url,
        "SELECT id, base_url, secret_sha256, status, updated_at FROM identity.services WHERE id <> 'newsvc' ORDER BY id",
    )
    assert after == before


# --------------------------------------------------------------------------- audit


async def test_every_administrative_action_is_audited_without_secrets(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any], owner_url: str
) -> None:
    client, user = admin
    dev, dev_user = await person()
    await grant(client, dev_user, ["staging"])
    await register(client)
    await send(client, "PATCH", "/services/newsvc", {"description": "x"})
    await send(client, "POST", "/services/newsvc/enable", {})
    await send(client, "POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc", "revoke_old": True})
    await send(client, "POST", "/services/newsvc/disable", {})
    await send(client, "DELETE", f"/developers/{dev_user.id}")
    actions = [
        r[0] for r in rows(owner_url, "SELECT action FROM identity.audit WHERE actor_id = %s ORDER BY id", user.id)
    ]
    for expected in (
        "developer_granted", "service_created", "service_secret_issued", "service_updated", "service_status_changed",
        "service_secret_rotated", "service_secret_revoked", "developer_revoked",
    ):  # fmt: skip
        assert expected in actions, expected
    activity = (await send(client, "GET", "/services/newsvc/activity")).json()["events"]
    assert activity[0]["actor"] == user.email and {"service_created", "service_status_changed"} <= {
        e["action"] for e in activity
    }


# --------------------------------------------------------------------------- developers


async def test_granting_and_revoking_developer_access(
    admin: tuple[httpx.AsyncClient, User], person: Callable[..., Any]
) -> None:
    admin_client, _ = admin
    dev, user = await person()
    assert (
        await send(admin_client, "PUT", "/developers", {"email": "nobody@example.com", "environments": ["local"]})
    ).status_code == 404
    await grant(admin_client, user, ["local", "staging"])
    listed = (await send(admin_client, "GET", "/developers")).json()["developers"]
    assert [(d["email"], d["environments"]) for d in listed] == [(user.email, ["local", "staging"])]
    assert (await register(dev, environment="local", base_url="http://localhost:9999")).status_code in (201, 422)
    assert (await send(admin_client, "DELETE", f"/developers/{user.id}")).status_code == 200
    assert (await send(dev, "GET", "/services")).status_code == 403
    assert (await send(admin_client, "DELETE", f"/developers/{user.id}")).status_code == 404
    assert (await send(admin_client, "DELETE", "/developers/not-a-uuid")).status_code == 404


async def test_a_suspended_account_loses_portal_access(admin: tuple[httpx.AsyncClient, User], owner_url: str) -> None:
    client, user = admin
    assert (await send(client, "GET", "/me")).status_code == 200
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE public.users SET status = 'suspended' WHERE id = %s", (user.id,))
    assert (await send(client, "GET", "/me")).status_code == 401


async def test_a_demoted_administrator_loses_administrator_powers(
    admin: tuple[httpx.AsyncClient, User], set_role: Callable[[User, str], None]
) -> None:
    client, user = admin
    await register(client)
    set_role(user, "beta_user")
    assert (await send(client, "GET", "/me")).status_code == 403  # the role is read on every request, never cached


# --------------------------------------------------------------------------- the pages


async def test_the_portal_pages_are_static_and_carry_the_security_headers(app: FastAPI) -> None:
    async with client_for(app) as anonymous:
        page = await anonymous.get("/developer/services")
        redirect = await anonymous.get("/developer")
        back = await anonymous.get("/handoff")
        script = await anonymous.get("/auth/static/developer/portal.js")
    assert page.status_code == 200 and "/auth/static/developer/boot.js" in page.text
    assert (
        "script-src 'self'" in page.headers["content-security-policy"] and page.headers["cache-control"] == "no-store"
    )
    assert page.headers["x-frame-options"] == "DENY"
    assert "token" not in page.text.lower()
    assert (redirect.status_code, redirect.headers["location"]) == (307, "/developer/services")
    assert back.status_code == 200 and "/auth/static/developer/return.js" in back.text
    assert script.status_code == 200 and "innerHTML" not in script.text.replace("never innerHTML", "")


# --------------------------------------------------------------------------- end to end: a portal-registered service


def product_app(app_identity: FastAPI, secret: str) -> FastAPI:
    from vetfab_identity_adapter import (
        AdapterConfig,
        HandoffConfig,
        HandoffRedeemer,
        IdentityAdapter,
        SessionCookie,
        VerifiedIdentity,
    )
    from vetfab_identity_adapter.fastapi import IdentityGuard, handoff_router

    adapter_config = AdapterConfig.build(auth_url=ORIGIN, environment="production")
    config = HandoffConfig.build(
        adapter_config, service_id="newsvc", service_secret=secret, session_secret="n" * 40, app_url=NEW_URL
    )
    identity_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app_identity), base_url=ORIGIN)
    sessions = SessionCookie(config)
    members: dict[UUID, str] = {}

    async def load_user(identity: VerifiedIdentity) -> str | None:
        return "member"

    guard: IdentityGuard[str] = IdentityGuard(
        IdentityAdapter(adapter_config, http=identity_http), load_user, sessions=sessions, app_origin=NEW_URL
    )
    product = FastAPI()
    product.include_router(
        handoff_router(
            HandoffRedeemer(adapter_config, config, http=identity_http), sessions, load_user, app_origin=NEW_URL
        )
    )
    del members, guard
    return product


async def land(product: FastAPI, ticket: str, origin: str) -> httpx.Response:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=product), base_url=NEW_URL) as http:
        return await http.post(
            "/handoff/redeem",
            content=f"ticket={ticket}",
            headers={"content-type": "application/x-www-form-urlencoded", "origin": origin},
        )


async def test_a_service_registered_in_the_portal_completes_a_real_handoff_until_it_is_disabled(
    admin: tuple[httpx.AsyncClient, User], app: FastAPI
) -> None:
    client, _ = admin
    secret = (await register(client)).json()["secret"]
    product = product_app(app, secret)

    async def ticket(target: str = "newsvc") -> httpx.Response:
        return await client.post(
            "/auth/handoff", json={"target": target, "return_to": "/home"}, headers={"origin": ORIGIN}
        )

    assert (await ticket()).status_code == 403  # pending: it cannot receive a handoff
    await send(client, "POST", "/services/newsvc/enable", {})
    grant_ = (await ticket()).json()
    assert grant_["redeem_url"] == f"{NEW_URL}/handoff/redeem"
    landed = await land(product, grant_["ticket"], ORIGIN)
    assert landed.status_code == 303 and landed.headers["location"] == "/home" and "set-cookie" in landed.headers

    pending_ticket = (await ticket()).json()["ticket"]
    await send(client, "POST", "/services/newsvc/disable", {})
    refused = await land(product, pending_ticket, ORIGIN)  # issued while active, redeemed after disabling
    assert refused.status_code == 400 and "set-cookie" not in refused.headers  # the disabled service is told so
    assert (await ticket()).status_code == 403  # no new handoffs to it
    reverse = await client.post("/auth/handoff", json={"target": "lms"}, headers={"origin": NEW_URL})
    assert reverse.status_code == 403  # nor from it


async def test_rotating_a_portal_secret_invalidates_the_old_one_as_documented(
    admin: tuple[httpx.AsyncClient, User], app: FastAPI
) -> None:
    client, _ = admin
    old = (await register(client)).json()["secret"]
    await send(client, "POST", "/services/newsvc/enable", {})
    new = (
        await send(client, "POST", "/services/newsvc/rotate-secret", {"confirm": "newsvc", "revoke_old": True})
    ).json()["secret"]

    async def attempt(secret: str) -> int:
        ticket = (await client.post("/auth/handoff", json={"target": "newsvc"}, headers={"origin": ORIGIN})).json()[
            "ticket"
        ]
        return (await land(product_app(app, secret), ticket, ORIGIN)).status_code

    assert await attempt(old) == 503  # the service's credentials are refused: an operator problem, not a bad ticket
    assert await attempt(new) == 303
