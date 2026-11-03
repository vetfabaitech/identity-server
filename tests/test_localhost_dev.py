"""Developing against the deployed identity service from localhost (IDENTITY_ALLOW_LOCALHOST_DEV_ORIGINS).

The setting is off by default and refused in production. When on, a `local` service whose base_url is exactly
`http://localhost:<port>` or `http://127.0.0.1:<port>` is activated as soon as a developer registers it (no administrator step) and
receives sign-ins through `GET /auth/login` and the `<origin>/handoff#token=...` redirect. It gets no CORS
answer, no switcher entry and no hand-off tickets, and nothing else ever accepts plain http on a deployed service.
"""

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import psycopg
import pytest
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from identity.config import Settings
from identity.redirects import post_signin_target, post_signout_target
from identity.services import RegistryError, clean_fields, is_localhost_dev_origin
from identity.store import User
from tests.conftest import ORIGIN, PASSWORD, SAME_ORIGIN, build_app, client_for, make_settings

LOCAL = "http://localhost:8765"
EVIL = "https://evil.example"


def clean(raw: dict[str, Any], *, deployed: bool = True, allow: bool = True) -> dict[str, Any]:
    return clean_fields(raw, deployed=deployed, label="test", require_secret_hash=False, allow_localhost_dev=allow)


def fields(**overrides: Any) -> dict[str, Any]:
    return {"id": "mydev", "display_name": "My dev", "base_url": LOCAL, "environment": "local", **overrides}


def settings_for(environment: str = "staging", **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": environment,
        "database_url": "postgresql://x@db/lms",
        "issuer": f"{ORIGIN}/auth",
        "audience": "vetfab",
        "app_origins": ORIGIN,
        "keys_dir": Path("/keys"),
        **overrides,
    }
    return Settings(_env_file=None, **values)  # pyright: ignore[reportCallIssue]


# --------------------------------------------------------------------------- validation (no database)


@pytest.mark.parametrize(
    ("given", "stored"),
    [
        (LOCAL, LOCAL),
        ("http://127.0.0.1:3000", "http://127.0.0.1:3000"),
        ("http://localhost:1024", "http://localhost:1024"),
        ("http://127.0.0.1:65535", "http://127.0.0.1:65535"),
        ("http://LOCALHOST:8765/", LOCAL),
    ],
)
def test_a_local_service_may_use_a_loopback_origin_with_a_port(given: str, stored: str) -> None:
    assert clean(fields(base_url=given))["base_url"] == stored


@pytest.mark.parametrize(
    "base_url",
    [
        "http://example.com:8765",  # no other http host
        "http://localhost",  # no port
        "http://localhost:80",  # a default port normalises away, and is below 1024 anyway
        "http://localhost:1023",
        "http://localhost:65536",
        "http://localhost:0",
        "http://localhost:8765/app",  # no path
        "http://localhost:8765?x=1",
        "http://user@localhost:8765",  # no userinfo
        "http://localhost:8765@evil.example",
        "http://localhost.evil.example:8765",
        "http://127.0.0.1.evil.example:8765",
        "http://[::1]:8765",
        "http://0.0.0.0:8765",
        "http://192.168.1.5:8765",
        "http://*.localhost:8765",
        "https://example.com",  # a local service on a deployed identity is loopback http or nothing
        "https://localhost:8765",
    ],
)
def test_nothing_but_a_loopback_origin_with_a_port_is_accepted(base_url: str) -> None:
    with pytest.raises(RegistryError):
        clean(fields(base_url=base_url))
    assert not is_localhost_dev_origin(base_url.rstrip("/"))


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_only_a_local_service_may_use_a_localhost_origin(environment: str) -> None:
    with pytest.raises(RegistryError, match="https"):
        clean(fields(environment=environment))


def test_the_setting_off_refuses_a_localhost_origin_on_a_deployed_service() -> None:
    with pytest.raises(RegistryError, match="https"):
        clean(fields(), allow=False)


def test_a_development_identity_service_is_unaffected_by_the_setting() -> None:
    assert clean(fields(), deployed=False, allow=False)["base_url"] == LOCAL
    assert clean(fields(), deployed=False, allow=True)["base_url"] == LOCAL


def test_deployed_https_rules_are_unchanged_whatever_the_setting() -> None:
    for allow in (True, False):
        assert clean(fields(base_url="https://lms.example", environment="staging"), allow=allow)
        assert clean(fields(base_url="https://lms.example", environment="production"), allow=allow)
        for bad in (
            fields(base_url="http://lms.example", environment="staging"),
            fields(base_url="http://lms.example", environment="production"),
            fields(base_url="https://lms.example", environment="local"),
            fields(base_url="http://lms.example", environment="local"),
        ):
            with pytest.raises(RegistryError):
                clean(bad, allow=allow)


# --------------------------------------------------------------------------- the setting


def test_the_setting_is_off_by_default() -> None:
    assert settings_for().allow_localhost_dev_origins is False


def test_the_setting_is_refused_in_production() -> None:
    with pytest.raises(ValueError, match="ALLOW_LOCALHOST_DEV_ORIGINS"):
        settings_for("production", allow_localhost_dev_origins=True)
    assert settings_for("staging", allow_localhost_dev_origins=True).allow_localhost_dev_origins


def test_plain_http_app_origins_are_still_refused_on_a_deployed_service() -> None:
    with pytest.raises(ValueError, match="https"):
        settings_for(app_origins=f"{ORIGIN},{LOCAL}", allow_localhost_dev_origins=True)


def test_a_localhost_origin_gets_no_cors_on_a_deployed_service() -> None:
    from starlette.requests import Request

    from identity.web.security import cors_headers, same_origin

    deployed = settings_for(allow_localhost_dev_origins=True)
    deployed.app_origins = f"{ORIGIN},{LOCAL}"  # what the registry cache does for an active local service
    assert LOCAL in deployed.app_origin_list and deployed.cors_origin_list == [ORIGIN]

    def request(headers: dict[str, str]) -> Request:
        raw = [(k.encode(), v.encode()) for k, v in headers.items()]
        return Request({"type": "http", "method": "POST", "path": "/", "headers": raw, "query_string": b""})

    assert cors_headers(request({"origin": LOCAL}), deployed) is None
    assert cors_headers(request({"origin": ORIGIN}), deployed) is not None
    assert not same_origin(request({"origin": LOCAL}), deployed, allow_siblings=True)
    development = settings_for("development", issuer="http://localhost:8200/auth", app_origins=LOCAL)
    assert development.cors_origin_list == [LOCAL]  # a development identity service is unchanged


# --------------------------------------------------------------------------- redirects (no database)


def trusting_local() -> Settings:
    """Settings as the registry cache leaves them once a local service is active."""
    trusted = settings_for(allow_localhost_dev_origins=True)
    trusted.app_origins = f"{ORIGIN},{LOCAL}"
    return trusted


def test_a_sign_in_may_return_to_the_trusted_localhost_origin() -> None:
    target = post_signin_target(f"{LOCAL}/learn?x=1", trusting_local())
    assert (target.origin, target.path, target.handoff_base) == (LOCAL, "/learn?x=1", f"{LOCAL}/handoff")
    assert post_signin_target(LOCAL, trusting_local()).path == "/"


@pytest.mark.parametrize(
    "value",
    [
        "http://localhost.evil.com",
        "http://localhost.evil.com/x",
        "http://localhost@evil.com",
        "http://localhost:8765@evil.com/x",
        "http://localhost:8765.evil.com/x",
        "http://localhost:8766/x",  # another port
        "http://localhost:87/x",
        "http://localhost/x",
        "http://127.0.0.1:8765/x",  # same port, other spelling: not registered
        "https://localhost:8765/x",  # other scheme
        "http://localhost:8765\\@evil.com",
        "http://localhost:8765?next=//evil.com",
        "http://localhost:8765#//evil.com",
    ],
)
def test_look_alikes_of_the_localhost_origin_are_not_followed(value: str) -> None:
    target = post_signin_target(value, trusting_local())
    assert target.origin == ORIGIN
    assert target.handoff_base == f"{ORIGIN}/handoff"


def test_a_path_after_the_localhost_origin_cannot_leave_it() -> None:
    target = post_signin_target(f"{LOCAL}//evil.example/x", trusting_local())
    assert (target.origin, target.path) == (LOCAL, "/")
    target = post_signin_target(f"{LOCAL}/../../x", trusting_local())
    assert (target.origin, urlsplit(f"{target.origin}{target.path}").netloc) == (LOCAL, "localhost:8765")


def test_the_localhost_origin_is_not_trusted_until_it_is_in_the_allowlist() -> None:
    target = post_signin_target(f"{LOCAL}/learn", settings_for(allow_localhost_dev_origins=True))
    assert target.origin == ORIGIN


def test_sign_out_may_return_to_the_trusted_localhost_origin_and_nowhere_look_alike() -> None:
    assert post_signout_target(f"{LOCAL}/bye", trusting_local()) == f"{LOCAL}/bye"
    for value in ("http://localhost.evil.com/", "http://localhost@evil.com/", "http://localhost:9999/"):
        assert "evil" not in post_signout_target(value, trusting_local()) and ":9999" not in post_signout_target(
            value, trusting_local()
        )


# --------------------------------------------------------------------------- over HTTP, on the throwaway database


def db_test(fn: Callable[..., Any]) -> Callable[..., Any]:
    return pytest.mark.db(pytest.mark.usefixtures("clear_attempts")(fn))


def make_app(login_url: str, pool: AsyncConnectionPool[Any], keys_dir: Path, *, allow: bool) -> FastAPI:
    settings = make_settings(login_url, keys_dir, allow_localhost_dev_origins=allow)
    return build_app(settings, pool, keys_dir)  # type: ignore[return-value]


@pytest.fixture
def on_app(login_url: str, pool: AsyncConnectionPool[Any], keys_dir: Path) -> FastAPI:
    return make_app(login_url, pool, keys_dir, allow=True)


@pytest.fixture
def off_app(login_url: str, pool: AsyncConnectionPool[Any], keys_dir: Path) -> FastAPI:
    return make_app(login_url, pool, keys_dir, allow=False)


async def sign_in(app: FastAPI, user: User) -> httpx.AsyncClient:
    client = client_for(app)
    response = await client.post(
        "/auth/login",
        data={"email": user.email, "password": PASSWORD, "redirect": "/", "state": "s"},
        headers=SAME_ORIGIN,
    )
    assert response.status_code == 303
    return client


async def api(client: httpx.AsyncClient, method: str, path: str, body: Any = None) -> httpx.Response:
    return await client.request(method, f"/auth/admin{path}", json=body, headers={"origin": ORIGIN})


def local_draft(**overrides: Any) -> dict[str, Any]:
    return {"id": "mydev", "display_name": "My dev", "environment": "local", "base_url": LOCAL, **overrides}


def audit_rows(owner_url: str, where: str = "true", *, after: int = 0) -> list[tuple[str, dict[str, Any]]]:
    with psycopg.connect(owner_url, autocommit=True) as conn:
        query = f"SELECT action, metadata FROM identity.audit WHERE id > {after} AND ({where}) ORDER BY id"  # noqa: S608
        return conn.execute(query).fetchall()  # type: ignore[arg-type, return-value]


def audit_mark(owner_url: str) -> int:
    with psycopg.connect(owner_url, autocommit=True) as conn:
        row = conn.execute("SELECT coalesce(max(id), 0) FROM identity.audit").fetchone()
    return int(row[0]) if row else 0


class People:
    """An administrator and a developer granted `local`, both signed in to one app."""

    def __init__(self, owner_url: str, make_user: Callable[..., User]) -> None:
        self.owner_url, self.make_user = owner_url, make_user

    async def start(self, app: FastAPI) -> None:
        admin_user, dev_user = self.make_user(password=PASSWORD), self.make_user(password=PASSWORD)
        with psycopg.connect(self.owner_url, autocommit=True) as conn:
            conn.execute("UPDATE public.users SET role = 'admin' WHERE id = %s", (admin_user.id,))
        self.admin, self.dev = await sign_in(app, admin_user), await sign_in(app, dev_user)
        self.dev_user = dev_user
        granted = await api(
            self.admin, "PUT", "/developers", {"email": dev_user.email, "environments": ["local", "staging"]}
        )
        assert granted.status_code == 200, granted.text

    async def close(self) -> None:
        await self.admin.aclose()
        await self.dev.aclose()


@pytest.fixture
async def people(owner_url: str, make_user: Callable[..., User], on_app: FastAPI) -> Any:
    group = People(owner_url, make_user)
    await group.start(on_app)
    yield group
    await group.close()


@db_test
async def test_a_developer_registers_a_localhost_origin_and_a_sign_in_lands_on_it_without_an_administrator(
    on_app: FastAPI, people: People, owner_url: str, make_user: Callable[..., User], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="identity")
    mark = audit_mark(owner_url)
    registered = await api(people.dev, "POST", "/services", local_draft())
    assert registered.status_code == 201, registered.text
    assert registered.json()["service"]["status"] == "active"
    secret = registered.json()["secret"]
    anonymous = client_for(on_app)
    wanted = {"redirect": f"{LOCAL}/learn", "state": "abc"}

    assert LOCAL in on_app.state.settings.app_origin_list
    assert f'value="{LOCAL}/learn"' in (await anonymous.get("/auth/login", params=wanted)).text

    user = make_user(password=PASSWORD)
    signed_in = await anonymous.post(
        "/auth/login", data={"email": user.email, "password": PASSWORD, **wanted}, headers=SAME_ORIGIN
    )
    assert signed_in.status_code == 303
    location = signed_in.headers["location"]
    assert location.startswith(f"{LOCAL}/handoff#token=") and "redirect=%2Flearn" in location
    assert "state=abc" in location

    # Silent single sign-on (a live session) lands there too, and is audited the same way.
    silent = await people.dev.get("/auth/login", params=wanted)
    assert silent.status_code == 303 and silent.headers["location"].startswith(f"{LOCAL}/handoff#token=")

    audited = dict.fromkeys(a for a, _ in audit_rows(owner_url, "metadata->>'local_origin' = 'true'", after=mark))
    assert {"service_created", "service_status_changed", "signin", "refresh"} <= set(audited)
    automatic = audit_rows(owner_url, "action = 'service_status_changed'", after=mark)
    assert [m["auto_approved"] for _, m in automatic] == [True]
    for action, metadata in audit_rows(
        owner_url, "action IN ('signin', 'refresh') AND metadata ? 'local_origin'", after=mark
    ):
        assert metadata == {"service": "mydev", "local_origin": True, "origin": LOCAL}, action
    messages = " ".join(r.getMessage() for r in caplog.records)
    for event in ("registered", "activated", "sign-in handed"):
        assert event in messages
    assert secret not in messages and "token=" not in messages
    assert secret not in str(audit_rows(owner_url, after=mark))


@db_test
async def test_other_sign_ins_are_not_marked_as_local(
    on_app: FastAPI, people: People, owner_url: str, make_user: Callable[..., User]
) -> None:
    await api(people.dev, "POST", "/services", local_draft())
    mark = audit_mark(owner_url)
    user = make_user(password=PASSWORD)
    await client_for(on_app).post(
        "/auth/login", data={"email": user.email, "password": PASSWORD, "redirect": "/learn"}, headers=SAME_ORIGIN
    )
    rows = audit_rows(owner_url, "action = 'signin'", after=mark)
    assert len(rows) == 1 and "local_origin" not in rows[0][1]


@db_test
async def test_a_developer_cannot_use_the_local_path_to_trust_anything_but_localhost(
    on_app: FastAPI, people: People, owner_url: str
) -> None:
    mark = audit_mark(owner_url)
    for index, base_url in enumerate(
        [
            "http://evil.example:8765",
            "http://localhost.evil.example:8765",
            "http://localhost",
            "http://localhost:8765/app",
            "http://user@localhost:8765",
            "https://evil.example",
            "http://169.254.169.254:8080",
        ]
    ):
        refused = await api(people.dev, "POST", "/services", local_draft(id=f"try{index}", base_url=base_url))
        assert refused.status_code == 422, (base_url, refused.text)
    for environment in ("staging", "production"):
        refused = await api(people.dev, "POST", "/services", local_draft(environment=environment))
        assert refused.status_code in (403, 422)
        refused = await api(people.admin, "POST", "/services", local_draft(id="adm", environment=environment))
        assert refused.status_code == 422, refused.text
    assert audit_rows(owner_url, "action = 'service_created'", after=mark) == []
    assert LOCAL not in on_app.state.settings.app_origin_list


@db_test
async def test_the_setting_off_refuses_registration_and_makes_an_activated_origin_inert(
    on_app: FastAPI, off_app: FastAPI, people: People, owner_url: str, make_user: Callable[..., User]
) -> None:
    await api(people.dev, "POST", "/services", local_draft())
    off_user = make_user(password=PASSWORD)
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("UPDATE public.users SET role = 'admin' WHERE id = %s", (off_user.id,))
    off_admin = await sign_in(off_app, off_user)
    try:
        # Setting off: registering is refused.
        assert (await api(off_admin, "POST", "/services", local_draft(id="second"))).status_code in (403, 422)

        # Active in the database, but an instance with the setting off trusts nothing and redirects nowhere.
        wanted = {"email": make_user(password=PASSWORD).email, "password": PASSWORD, "redirect": f"{LOCAL}/learn"}
        landed = await client_for(off_app).post("/auth/login", data=wanted, headers=SAME_ORIGIN)
        assert landed.status_code == 303 and landed.headers["location"].startswith(f"{ORIGIN}/handoff#token=")
        assert LOCAL not in off_app.state.settings.app_origin_list
        assert LOCAL not in (await client_for(off_app).get("/auth/health")).headers["content-security-policy"]
        assert LOCAL in on_app.state.settings.app_origin_list
    finally:
        await off_admin.aclose()


@db_test
async def test_an_inactive_or_disabled_local_service_gets_no_sign_in(
    on_app: FastAPI, people: People, make_user: Callable[..., User]
) -> None:
    await api(people.dev, "POST", "/services", local_draft())
    assert (await api(people.dev, "POST", "/services/mydev/disable", {})).status_code == 200
    assert LOCAL not in on_app.state.settings.app_origin_list
    form = {"email": make_user(password=PASSWORD).email, "password": PASSWORD, "redirect": f"{LOCAL}/learn"}
    landed = await client_for(on_app).post("/auth/login", data=form, headers=SAME_ORIGIN)
    assert landed.headers["location"].startswith(f"{ORIGIN}/handoff#token=")


@db_test
async def test_open_redirect_attempts_never_reach_another_host(
    on_app: FastAPI, people: People, make_user: Callable[..., User]
) -> None:
    await api(people.dev, "POST", "/services", local_draft())
    user = make_user(password=PASSWORD)
    for value in (
        "http://localhost.evil.com/x",
        "http://localhost@evil.com/x",
        "http://localhost:8765@evil.com/x",
        "http://localhost:9999/x",
        "http://127.0.0.1:8765/x",
    ):
        form = {"email": user.email, "password": PASSWORD, "redirect": value}
        response = await client_for(on_app).post("/auth/login", data=form, headers=SAME_ORIGIN)
        assert response.headers["location"].startswith(f"{ORIGIN}/handoff#token="), value


@db_test
async def test_a_localhost_origin_gets_no_cors_no_switcher_entry_and_no_hand_off(
    on_app: FastAPI, people: People
) -> None:
    registered = await api(people.dev, "POST", "/services", local_draft())
    secret = registered.json()["secret"]
    anonymous = client_for(on_app)
    for path in ("/auth/session/token", "/auth/handoff", "/auth/services"):
        preflight = await anonymous.options(path, headers={"origin": LOCAL})
        assert preflight.status_code == 403 and "access-control-allow-origin" not in preflight.headers
    renewal = await people.dev.post("/auth/session/token", headers={"origin": LOCAL})
    assert (renewal.status_code, renewal.json()) == (403, {"error": "origin"})
    assert "access-control-allow-origin" not in renewal.headers
    listing = await people.dev.get("/auth/services", headers={"origin": LOCAL})
    assert listing.status_code == 403 and "access-control-allow-origin" not in listing.headers
    # The allowlisted https origin still works, and the local service is not offered to anyone.
    assert (await anonymous.options("/auth/session/token", headers={"origin": ORIGIN})).status_code == 204
    shown = (await people.dev.get("/auth/services", headers={"origin": ORIGIN})).json()["services"]
    assert "mydev" not in [s["id"] for s in shown]
    # It cannot redeem tickets either: its credentials are refused like a disabled service's.
    redeemed = await anonymous.post("/auth/handoff/redeem", auth=("mydev", secret), json={"ticket": "x"})
    assert redeemed.status_code == 403


@db_test
async def test_sign_out_may_return_to_the_localhost_origin(on_app: FastAPI, people: People) -> None:
    await api(people.dev, "POST", "/services", local_draft())
    out = await people.dev.post("/auth/logout", params={"redirect": f"{LOCAL}/bye"}, headers=SAME_ORIGIN)
    assert (out.status_code, out.headers["location"]) == (303, f"{LOCAL}/bye")
    again = await people.admin.post(
        "/auth/logout", params={"redirect": "http://localhost.evil.com/"}, headers=SAME_ORIGIN
    )
    assert "evil" not in again.headers["location"]


@db_test
async def test_only_a_localhost_origin_is_activated_on_registration(on_app: FastAPI, people: People) -> None:
    staging = await api(people.dev, "POST", "/services", local_draft(id="stg", environment="staging", base_url=EVIL))
    assert staging.status_code == 201 and staging.json()["service"]["status"] == "pending"
    assert EVIL not in on_app.state.settings.app_origin_list
    # A developer may disable their own localhost service but still cannot bring it back: that is an administrator's.
    await api(people.dev, "POST", "/services", local_draft())
    assert (await api(people.dev, "POST", "/services/mydev/disable", {})).status_code == 200
    again = await api(people.dev, "POST", "/services/mydev/enable", {})
    assert (again.status_code, again.json()["error"]) == (403, "administrator_only")
