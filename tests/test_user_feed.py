"""The signed user feed over HTTP (CONTRACT.md, "User feed"): who may read it, what a document looks like and how a
consumer verifies it, the three endpoints' paging and bounds, purge and gap semantics, and the rate limit.

`verify_document` below is what a consumer must check; the LMS's client does the same.
"""

import base64
import hashlib
import json
import re
import uuid
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import jwt
import psycopg
import pytest
from fastapi import FastAPI
from jwt import PyJWK
from psycopg_pool import AsyncConnectionPool

from identity.config import Settings
from identity.keys import KeyRing
from identity.store import User
from identity.tokens import mint_access_token
from tests.conftest import ORIGIN, build_app, client_for, make_settings
from tests.contract.verifier import InvalidTokenError as LmsInvalid
from tests.contract.verifier import JwksKeyStore, JwksSource, TokenPolicy, TokenVerifier
from vetfab_identity_adapter import AdapterConfig, IdentityAdapter
from vetfab_identity_adapter import InvalidTokenError as AdapterInvalid

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("clear_attempts")]

ISSUER = "https://test.vetfab.ai/auth"
REPORTS, IDE, OLD = "https://reports.vetfab.ai", "https://ide.vetfab.ai", "https://old.vetfab.ai"
SECRETS = {"lms": "lms-feed-secret", "reports": "reports-secret", "ide": "ide-secret", "old": "old-secret"}
PATHS = ["/auth/service/user-events", f"/auth/service/users/{uuid.uuid4()}", "/auth/service/users"]
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def entry(sid: str, url: str, **extra: Any) -> dict[str, Any]:
    return {"id": sid, "display_name": sid.upper(), "base_url": url, "secret_sha256": sha(SECRETS[sid]), **extra}


REGISTRY = json.dumps(
    {
        "services": [
            entry("lms", ORIGIN),
            entry("reports", REPORTS),
            entry("ide", IDE),
            entry("old", OLD, enabled=False),
        ]
    }
)
ALLOWED = "lms,reports,old,waiting"  # `ide` is active but not allowed; `old` and `waiting` are allowed but not active


def basic(service_id: str, secret: str | None = None) -> dict[str, str]:
    token = base64.b64encode(f"{service_id}:{secret or SECRETS[service_id]}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def feed_settings(login_url: str, keys_dir: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "app_origins": ",".join([ORIGIN, REPORTS, IDE, OLD]),
        "services": REGISTRY,
        "user_feed_services": ALLOWED,
        **overrides,
    }
    return make_settings(login_url, keys_dir, **values)


@pytest.fixture
def app(login_url: str, pool: AsyncConnectionPool, keys_dir: Path, owner_url: str) -> FastAPI:
    with psycopg.connect(owner_url, autocommit=True) as conn:  # a registered service still waiting for approval
        conn.execute(
            """INSERT INTO identity.services (id, display_name, environment, base_url, secret_sha256, status)
               VALUES ('waiting', 'Waiting', 'staging', 'https://waiting.vetfab.ai', %s, 'pending')""",
            (sha("waiting-secret"),),
        )
    built = build_app(feed_settings(login_url, keys_dir), pool, keys_dir)
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


def head(conn: psycopg.Connection[Any]) -> int:
    row = conn.execute("SELECT coalesce(max(seq), 0) FROM identity.user_events").fetchone()
    assert row is not None
    return row[0]


async def verify_document(
    client: httpx.AsyncClient, response: httpx.Response, *, audience: str = "lms", kind: str | None = None
) -> dict[str, Any]:
    """What a consumer checks: 200 application/jwt, RS256 under typ user-feed+jwt with a kid from the JWKS, a valid
    signature, the identity issuer, its own service id as audience, unexpired, and the expected kind."""
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/jwt"
    assert response.headers["cache-control"] == "no-store"
    token = response.text
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256" and header["typ"] == "user-feed+jwt"
    jwks = (await client.get("/auth/.well-known/jwks.json")).json()
    match = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    claims = jwt.decode(
        token,
        key=PyJWK.from_dict(match, algorithm="RS256"),
        algorithms=["RS256"],
        audience=audience,
        issuer=ISSUER,
        options={"require": ["iss", "aud", "iat", "exp", "jti"]},
    )
    if kind is not None:
        assert claims["kind"] == kind
    return claims


async def events(client: httpx.AsyncClient, **params: Any) -> dict[str, Any]:
    response = await client.get("/auth/service/user-events", params=params, headers=basic("lms"))
    return await verify_document(client, response, kind="user-events")


def mine(body: dict[str, Any], *ids: UUID) -> list[dict[str, Any]]:
    wanted = {str(i) for i in ids}
    return [e for e in body["events"] if e["user"]["id"] in wanted]


# --------------------------------------------------------------------------- who may read the feed


def assert_invalid_client(response: httpx.Response) -> None:
    assert response.status_code == 401
    assert response.json() == {"detail": {"code": "invalid_client"}}
    assert response.headers["www-authenticate"] == 'Basic realm="vetfab-identity"'
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "Bearer abc",
        "Basic !!!not-base64",
        "Basic " + base64.b64encode(b"lms").decode(),
        "Basic " + base64.b64encode(b"lms:").decode(),
        "Basic " + base64.b64encode(b"lms:wrong-secret").decode(),
        "Basic " + base64.b64encode(b"nobody:lms-feed-secret").decode(),
        "Basic " + base64.b64encode(b"ide:lms-feed-secret").decode(),
    ],
)
async def test_bad_or_missing_credentials_are_401(
    client: httpx.AsyncClient, path: str, authorization: str | None
) -> None:
    headers = {"Authorization": authorization} if authorization else {}
    assert_invalid_client(await client.get(path, headers=headers))


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize(
    "credentials",
    [
        basic("ide"),  # active, but not in IDENTITY_USER_FEED_SERVICES
        basic("old"),  # allowed, but disabled
        basic("waiting", "waiting-secret"),  # allowed, but still pending approval
    ],
)
async def test_a_service_that_is_not_active_and_allowed_is_403(
    client: httpx.AsyncClient, path: str, credentials: dict[str, str]
) -> None:
    response = await client.get(path, headers=credentials)
    assert response.status_code == 403
    assert response.json() == {"detail": {"code": "user_feed_not_allowed"}}
    assert response.headers["cache-control"] == "no-store"


async def test_an_empty_allowlist_switches_the_feed_off(
    login_url: str, pool: AsyncConnectionPool, keys_dir: Path
) -> None:
    app = build_app(feed_settings(login_url, keys_dir, user_feed_services=""), pool, keys_dir)
    async with client_for(app) as c:
        for path in PATHS:
            response = await c.get(path, headers=basic("lms"))
            assert (response.status_code, response.json()) == (403, {"detail": {"code": "user_feed_not_allowed"}})


async def test_disabling_a_service_stops_its_feed_at_once(client: httpx.AsyncClient, owner_conn: Any) -> None:
    assert (await client.get(PATHS[0], headers=basic("lms"))).status_code == 200
    owner_conn.execute("UPDATE identity.services SET status = 'disabled' WHERE id = 'lms'")
    assert (await client.get(PATHS[0], headers=basic("lms"))).status_code == 403


async def test_the_previous_secret_works_only_inside_its_rotation_grace(
    client: httpx.AsyncClient, owner_conn: Any
) -> None:
    """The same rotation rule as hand-off redemption: rotate, and the old secret keeps working for the grace window."""
    assert (await client.get(PATHS[0], headers=basic("lms"))).status_code == 200  # seeds the registry
    rotated = owner_conn.execute(
        """UPDATE identity.services SET previous_secret_sha256 = secret_sha256, secret_sha256 = %s,
                  previous_secret_expires_at = now() + interval '1 hour' WHERE id = 'lms'""",
        (sha("lms-rotated-secret"),),
    )
    assert rotated.rowcount == 1
    assert (await client.get(PATHS[0], headers=basic("lms", "lms-rotated-secret"))).status_code == 200
    assert (await client.get(PATHS[0], headers=basic("lms"))).status_code == 200
    owner_conn.execute(
        "UPDATE identity.services SET previous_secret_expires_at = now() - interval '1 second' WHERE id = 'lms'"
    )
    assert_invalid_client(await client.get(PATHS[0], headers=basic("lms")))
    assert (await client.get(PATHS[0], headers=basic("lms", "lms-rotated-secret"))).status_code == 200


async def test_browsers_get_no_cors_answer(client: httpx.AsyncClient) -> None:
    response = await client.get(PATHS[0], headers={**basic("lms"), "origin": ORIGIN})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


# --------------------------------------------------------------------------- the document


async def test_a_document_is_signed_with_the_published_access_token_key(
    client: httpx.AsyncClient, keys_dir: Path
) -> None:
    first = await client.get("/auth/service/user-events", headers=basic("reports"))
    claims = await verify_document(client, first, audience="reports", kind="user-events")
    header = jwt.get_unverified_header(first.text)
    assert header == {"alg": "RS256", "typ": "user-feed+jwt", "kid": KeyRing.load(keys_dir).signing_kid}
    assert claims["iss"] == ISSUER and claims["aud"] == "reports"
    assert claims["exp"] - claims["iat"] == 300
    common = {"iss", "aud", "iat", "exp", "jti", "kind"}
    assert set(claims) == common | {"after", "limit", "events", "next", "head", "oldest"}
    listing = await verify_document(
        client, await client.get("/auth/service/users", headers=basic("reports")), audience="reports"
    )
    assert set(listing) == common | {"after", "limit", "users", "next", "head"}
    one = await verify_document(
        client, await client.get(f"/auth/service/users/{uuid.uuid4()}", headers=basic("reports")), audience="reports"
    )
    assert set(one) == common | {"user"}
    second = await client.get("/auth/service/user-events", headers=basic("reports"))
    assert (await verify_document(client, second, audience="reports"))["jti"] != claims["jti"]


async def test_a_document_for_one_service_is_refused_by_another(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/service/users", headers=basic("reports"))
    with pytest.raises(jwt.InvalidAudienceError):
        await verify_document(client, response, audience="lms")


async def test_access_token_verifiers_refuse_a_feed_document(
    client: httpx.AsyncClient, keys_dir: Path, tmp_path: Path
) -> None:
    """The distinct `typ` keeps the two apart: a feed document is never an access token... (a single-user document,
    small enough that the verifiers reach the `typ` check rather than refusing it for its length)"""
    document = (await client.get(f"/auth/service/users/{uuid.uuid4()}", headers=basic("lms"))).text
    assert len(document) < 8192
    ring = KeyRing.load(keys_dir)
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps(ring.jwks()))
    lms = TokenVerifier(TokenPolicy(issuer=ISSUER, audience="vetfab"), JwksKeyStore(JwksSource(file=jwks_file)))
    with pytest.raises(LmsInvalid, match="not an access token"):
        await lms.verify(document)
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=ring.jwks())))
    config = AdapterConfig.build(
        auth_url="https://test.vetfab.ai", environment="production", issuer=ISSUER, audience="vetfab"
    )
    with pytest.raises(AdapterInvalid):
        await IdentityAdapter(config, http=http).verify(document)


async def test_a_feed_consumer_refuses_an_access_token(
    client: httpx.AsyncClient, keys_dir: Path, settings: Settings
) -> None:
    """...and an access token, even one addressed to the service id, is never a feed document."""
    token = mint_access_token(KeyRing.load(keys_dir), settings.model_copy(update={"audience": "lms"}), uuid.uuid4())
    forged = httpx.Response(200, text=token, headers={"content-type": "application/jwt", "cache-control": "no-store"})
    with pytest.raises(AssertionError):
        await verify_document(client, forged)


# --------------------------------------------------------------------------- GET /auth/service/user-events


async def test_events_carry_the_snapshot_as_of_each_change(client: httpx.AsyncClient, owner_conn: Any) -> None:
    base = head(owner_conn)
    row = owner_conn.execute(
        "INSERT INTO public.users (email, display_name) VALUES (%s, 'Ada') RETURNING id, email",
        (f"{uuid.uuid4().hex[:10]}@feed.test",),
    ).fetchone()
    uid, email = row
    owner_conn.execute("UPDATE public.users SET display_name = 'Ada L', status = 'approved' WHERE id = %s", (uid,))
    owner_conn.execute("UPDATE public.users SET last_login_at = now(), role = 'admin' WHERE id = %s", (uid,))
    owner_conn.execute("DELETE FROM public.users WHERE id = %s", (uid,))
    body = await events(client, after=base)
    created, updated, gone = mine(body, uid)
    assert created["type"] == "user.created" and updated["type"] == "user.updated" and gone["type"] == "user.deleted"
    assert created["user"] == {
        "id": str(uid),
        "version": 1,
        "deleted": False,
        "email": email,
        "display_name": "Ada",
        "status": "pending",
    }
    assert updated["user"] == {**created["user"], "version": 2, "display_name": "Ada L", "status": "approved"}
    assert gone["user"] == {"id": str(uid), "version": 3, "deleted": True}  # no personal data
    assert created["seq"] < updated["seq"] < gone["seq"]
    assert all(RFC3339.match(e["occurred_at"]) for e in (created, updated, gone))
    assert body["next"] == body["events"][-1]["seq"]
    assert body["head"] >= body["next"] and body["oldest"] <= base + 1


async def test_events_page_forward_from_a_cursor(
    client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    base = head(owner_conn)
    made = [make_user() for _ in range(5)]
    pages: list[list[dict[str, Any]]] = []
    cursor = base
    while True:
        body = await events(client, after=cursor, limit=2)
        if not body["events"]:
            assert body["next"] == cursor  # an empty page leaves the cursor where it was
            break
        assert [e["seq"] for e in body["events"]] == sorted(e["seq"] for e in body["events"])
        assert all(e["seq"] > cursor for e in body["events"]) and len(body["events"]) <= 2
        pages.append(body["events"])
        cursor = body["next"]
    seen = [e for page in pages for e in page]
    assert [e["user"]["id"] for e in seen] == [str(u.id) for u in made]
    assert cursor == body["head"] == head(owner_conn)


async def test_a_cursor_past_the_head_gets_an_empty_page(client: httpx.AsyncClient, owner_conn: Any) -> None:
    beyond = head(owner_conn) + 1000
    body = await events(client, after=beyond)
    assert body["events"] == [] and body["next"] == beyond and body["head"] == head(owner_conn)


async def test_the_default_page_is_200_events_and_at_most_500(client: httpx.AsyncClient, owner_conn: Any) -> None:
    base = head(owner_conn)
    owner_conn.execute(
        """INSERT INTO public.users (email, display_name)
           SELECT 'bulk-' || g || '-' || %s || '@feed.test', 'Bulk' FROM generate_series(1, 501) g""",
        (uuid.uuid4().hex[:8],),
    )
    assert len((await events(client, after=base))["events"]) == 200
    assert len((await events(client, after=base, limit=500))["events"]) == 500
    assert len((await events(client, after=base, limit=1))["events"]) == 1


@pytest.mark.parametrize(
    ("params", "field"),
    [
        ({"limit": "0"}, "limit"),
        ({"limit": "501"}, "limit"),
        ({"limit": "-1"}, "limit"),
        ({"limit": "ten"}, "limit"),
        ({"limit": "1.5"}, "limit"),
        ({"limit": ""}, "limit"),
        ({"after": "-1"}, "after"),
        ({"after": "x"}, "after"),
        ({"after": str(2**63)}, "after"),
    ],
)
async def test_event_parameters_out_of_bounds_are_422(
    client: httpx.AsyncClient, params: dict[str, str], field: str
) -> None:
    response = await client.get("/auth/service/user-events", params=params, headers=basic("lms"))
    assert response.status_code == 422
    assert response.json() == {"detail": {"code": "invalid_request", "field": field}}


async def test_parameters_are_only_checked_for_an_authenticated_caller(client: httpx.AsyncClient) -> None:
    assert_invalid_client(await client.get("/auth/service/user-events?limit=0"))
    assert_invalid_client(await client.get("/auth/service/users/not-a-uuid"))


def age(conn: Any, through: int, days: int = 40) -> None:
    conn.execute(
        "UPDATE identity.user_events SET occurred_at = now() - make_interval(days => %s) WHERE seq <= %s",
        (days, through),
    )


async def test_after_a_purge_oldest_shows_a_consumer_its_gap(
    app: FastAPI, client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    await events(client)  # the first events request of an instance purges (nothing has expired yet)
    base = head(owner_conn)
    for _ in range(5):
        make_user()
    seqs = [e["seq"] for e in (await events(client, after=base))["events"]]
    assert len(seqs) == 5
    age(owner_conn, seqs[2])  # the first three, and everything before them, are past the retention
    unpurged = await events(client, after=base)
    assert unpurged["oldest"] <= seqs[0]  # at most one purge an hour per instance
    app.state.user_feed_purged_at = None  # an hour later
    body = await events(client, after=seqs[1])
    assert body["oldest"] == seqs[3] and body["head"] == seqs[4]
    assert [e["seq"] for e in body["events"]] == seqs[3:]  # seq 3 is gone with the purge
    behind, caught_up = seqs[1], seqs[2]
    assert behind + 1 < body["oldest"]  # a gap: this consumer reconciles from the list
    assert not caught_up + 1 < body["oldest"]  # no gap: it had seen everything that was purged


async def test_the_newest_event_survives_any_purge(
    app: FastAPI, client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    make_user()
    newest = head(owner_conn)
    age(owner_conn, newest)
    app.state.user_feed_purged_at = None
    body = await events(client)
    assert (body["head"], body["oldest"]) == (newest, newest)


async def test_with_no_events_retained_oldest_is_head_plus_one(client: httpx.AsyncClient, owner_conn: Any) -> None:
    owner_conn.execute("DELETE FROM identity.user_events")  # a database that has never recorded an event
    body = await events(client)
    assert (body["events"], body["next"], body["head"], body["oldest"]) == ([], 0, 0, 1)


# --------------------------------------------------------------------------- GET /auth/service/users/{id}


async def user(client: httpx.AsyncClient, user_id: object) -> dict[str, Any]:
    response = await client.get(f"/auth/service/users/{user_id}", headers=basic("lms"))
    return (await verify_document(client, response, kind="user"))["user"]


async def test_one_user_by_id(client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]) -> None:
    made = make_user(status="approved", name="Grace")
    owner_conn.execute("UPDATE public.users SET status = 'suspended' WHERE id = %s", (made.id,))
    assert await user(client, made.id) == {
        "id": str(made.id),
        "version": 2,
        "deleted": False,
        "email": made.email,
        "display_name": "Grace",
        "status": "suspended",
    }
    assert (await user(client, str(made.id).upper()))["id"] == str(made.id)  # answered in canonical form


async def test_an_unknown_id_is_deleted_at_version_0(client: httpx.AsyncClient) -> None:
    unknown = uuid.uuid4()
    assert await user(client, unknown) == {"id": str(unknown), "version": 0, "deleted": True}


async def test_a_deleted_user_carries_its_last_version(
    client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    made = make_user()
    owner_conn.execute("UPDATE public.users SET display_name = 'Renamed' WHERE id = %s", (made.id,))
    owner_conn.execute("DELETE FROM public.users WHERE id = %s", (made.id,))
    assert await user(client, made.id) == {"id": str(made.id), "version": 3, "deleted": True}


async def test_a_user_without_a_version_row_is_version_1(
    client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    made = make_user()
    owner_conn.execute("DELETE FROM identity.user_versions WHERE user_id = %s", (made.id,))
    assert (await user(client, made.id))["version"] == 1


@pytest.mark.parametrize("bad", ["not-a-uuid", "123", "0" * 31, f"{uuid.uuid4()}x", "x" * 100])
async def test_an_invalid_id_is_422(client: httpx.AsyncClient, bad: str) -> None:
    response = await client.get(f"/auth/service/users/{bad}", headers=basic("lms"))
    assert response.status_code == 422
    assert response.json() == {"detail": {"code": "invalid_request", "field": "id"}}


# --------------------------------------------------------------------------- GET /auth/service/users


async def users(client: httpx.AsyncClient, **params: Any) -> dict[str, Any]:
    response = await client.get("/auth/service/users", params=params, headers=basic("lms"))
    return await verify_document(client, response, kind="users")


async def test_the_list_pages_through_every_live_user_by_id(
    client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    for _ in range(3):
        make_user()
    gone = make_user()
    owner_conn.execute("DELETE FROM public.users WHERE id = %s", (gone.id,))
    expected = owner_conn.execute(
        """SELECT u.id::text, coalesce(v.version, 1) FROM public.users u
             LEFT JOIN identity.user_versions v ON v.user_id = u.id ORDER BY u.id"""
    ).fetchall()
    listed: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        body = await users(client, **({"after": cursor} if cursor else {}), limit=25)
        assert len(body["users"]) <= 25
        listed += body["users"]
        if body["next"] is None:
            break
        assert body["next"] == body["users"][-1]["id"]
        cursor = body["next"]
    assert [(u["id"], u["version"]) for u in listed] == [tuple(row) for row in expected]
    assert all(
        u["deleted"] is False and set(u) == {"id", "version", "deleted", "email", "display_name", "status"}
        for u in listed
    )
    assert str(gone.id) not in {u["id"] for u in listed}


async def test_next_is_null_exactly_on_the_last_page(
    client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    for _ in range(4):
        make_user()
    ids = [row[0] for row in owner_conn.execute("SELECT id::text FROM public.users ORDER BY id").fetchall()]
    start = ids[-4]  # three users follow it
    full = await users(client, after=start, limit=3)
    assert [u["id"] for u in full["users"]] == ids[-3:] and full["next"] is None  # a full last page ends the list
    short = await users(client, after=start, limit=2)
    assert [u["id"] for u in short["users"]] == ids[-3:-1] and short["next"] == ids[-2]
    rest = await users(client, after=short["next"], limit=2)
    assert [u["id"] for u in rest["users"]] == ids[-1:] and rest["next"] is None
    assert (await users(client, after=ids[-1]))["users"] == []


async def test_the_head_describes_the_page_it_came_with(
    client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    """Reconcile from the list, then read events from its head: a change made after the list is never missed."""
    made = make_user()
    listing = await users(client, limit=1000)
    assert listing["head"] == head(owner_conn)
    owner_conn.execute("UPDATE public.users SET display_name = 'After the list' WHERE id = %s", (made.id,))
    later = mine(await events(client, after=listing["head"]), made.id)
    assert [e["user"]["display_name"] for e in later] == ["After the list"]


@pytest.mark.parametrize(
    ("params", "field"),
    [
        ({"limit": "0"}, "limit"),
        ({"limit": "1001"}, "limit"),
        ({"limit": "a"}, "limit"),
        ({"after": "not-a-uuid"}, "after"),
        ({"after": ""}, "after"),
    ],
)
async def test_list_parameters_out_of_bounds_are_422(
    client: httpx.AsyncClient, params: dict[str, str], field: str
) -> None:
    response = await client.get("/auth/service/users", params=params, headers=basic("lms"))
    assert response.status_code == 422
    assert response.json() == {"detail": {"code": "invalid_request", "field": field}}


async def test_the_list_takes_up_to_1000_users_and_500_by_default(client: httpx.AsyncClient, owner_conn: Any) -> None:
    count = owner_conn.execute("SELECT count(*) FROM public.users").fetchone()[0]
    assert len((await users(client, limit=1000))["users"]) == min(count, 1000)
    assert len((await users(client))["users"]) == min(count, 500)


# --------------------------------------------------------------------------- a document echoes the request it answers


async def test_an_events_document_echoes_after_and_the_effective_limit(
    client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    """A still-valid document cannot be replayed as the answer to another request: the consumer compares these."""
    default = await events(client)
    assert (default["after"], default["limit"]) == (0, 200)
    base = head(owner_conn)
    make_user()
    explicit = await events(client, after=base, limit=7)
    assert (explicit["after"], explicit["limit"]) == (base, 7)
    beyond = head(owner_conn) + 5
    empty = await events(client, after=beyond, limit=3)
    assert (empty["after"], empty["limit"], empty["events"], empty["next"]) == (beyond, 3, [], beyond)


async def test_a_users_document_echoes_after_and_the_effective_limit(
    client: httpx.AsyncClient, owner_conn: Any, make_user: Callable[..., User]
) -> None:
    for _ in range(3):
        make_user()
    first = await users(client)
    assert (first["after"], first["limit"]) == (None, 500)
    ids = [row[0] for row in owner_conn.execute("SELECT id::text FROM public.users ORDER BY id").fetchall()]
    start = ids[-3]
    page = await users(client, after=start, limit=5)
    assert (page["after"], page["limit"]) == (start, 5)
    upper = await users(client, after=start.upper(), limit=5)
    assert upper["after"] == start  # echoed in canonical (lowercase) form


async def test_a_users_page_is_strictly_ascending_and_after_the_cursor(
    client: httpx.AsyncClient, make_user: Callable[..., User]
) -> None:
    for _ in range(5):
        make_user()
    cursor: str | None = None
    for _ in range(4):
        page = await users(client, **({"after": cursor} if cursor else {}), limit=3)
        ids = [UUID(u["id"]) for u in page["users"]]
        assert all(a < b for a, b in zip(ids, ids[1:], strict=False))  # strictly ascending, as Postgres orders uuids
        if cursor is not None:
            assert all(i > UUID(cursor) for i in ids)
        if page["next"] is None:
            break
        cursor = page["next"]


# --------------------------------------------------------------------------- rate limit


async def test_each_service_is_limited_on_its_own(login_url: str, pool: AsyncConnectionPool, keys_dir: Path) -> None:
    app = build_app(feed_settings(login_url, keys_dir, user_feed_rate_limit=10), pool, keys_dir)
    async with client_for(app) as c:
        for _ in range(10):
            assert (await c.get(PATHS[0], headers=basic("lms"))).status_code == 200
        limited = await c.get(PATHS[2], headers=basic("lms"))
        assert limited.status_code == 429
        assert limited.json() == {"detail": {"code": "too_many_requests"}}
        assert 1 <= int(limited.headers["retry-after"]) <= 600
        assert limited.headers["cache-control"] == "no-store"
        assert (await c.get(PATHS[0], headers=basic("reports"))).status_code == 200


async def test_the_default_limit_is_1200_per_600_seconds(client: httpx.AsyncClient, owner_conn: Any) -> None:
    owner_conn.execute(
        """INSERT INTO identity.signin_attempts (key, window_start, count)
           VALUES ('feed:lms', now() - interval '590 seconds', 1199)"""
    )
    assert (await client.get(PATHS[0], headers=basic("lms"))).status_code == 200  # the 1200th
    limited = await client.get(PATHS[0], headers=basic("lms"))
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["retry-after"]) <= 10  # the window ends in about 10 seconds
    owner_conn.execute(
        "UPDATE identity.signin_attempts SET window_start = now() - interval '601 seconds' WHERE key = 'feed:lms'"
    )
    assert (await client.get(PATHS[0], headers=basic("lms"))).status_code == 200  # a new window


async def test_a_busy_database_is_503_in_the_feed_shape(
    login_url: str, pool: AsyncConnectionPool, keys_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import asynccontextmanager

    from psycopg_pool import PoolTimeout

    @asynccontextmanager
    async def exhausted(*args: object, **kwargs: object) -> AsyncIterator[None]:
        raise PoolTimeout("couldn't get a connection")
        yield

    monkeypatch.setattr(pool, "connection", exhausted)
    async with client_for(build_app(feed_settings(login_url, keys_dir), pool, keys_dir)) as c:
        response = await c.get(PATHS[0], headers=basic("lms"))
    assert (response.status_code, response.json()) == (503, {"detail": {"code": "busy"}})
    assert response.headers["retry-after"] == "2" and response.headers["cache-control"] == "no-store"
