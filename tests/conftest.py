"""Test harness for the identity service.

* A throwaway database per session (`identity_test_<hex>`) on the local compose Postgres (or IDENTITY_TEST_ADMIN_URL),
  migrated to head on an empty database, the way the test box creates it.
* `login_url`: a dedicated NOINHERIT login that is a member of `identity_app` only, so every DB test runs with the
  privileges the deployed service has, never the owner's.
* Without a reachable database the `db` tests skip, unless IDENTITY_REQUIRE_DB=1 (CI).
"""

import os
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import psycopg
import pytest
from psycopg import sql

if TYPE_CHECKING:
    import httpx
    from psycopg_pool import AsyncConnectionPool

    from identity.config import Settings
    from identity.store import User

IDENTITY_DIR = Path(__file__).resolve().parent.parent
LMS_USERS_STUB = IDENTITY_DIR / "tests/fixtures/lms-users-stub.sql"

ADMIN_URL = os.environ.get(
    "IDENTITY_TEST_ADMIN_URL",
    "postgresql://identity:identity-local-only@127.0.0.1:54331/identity",
)
LOGIN_ROLE = "identity_test_login"
LOGIN_PASSWORD = "identity-test-only"  # noqa: S105  # local throwaway role


def db_url(name: str, *, user: str | None = None, password: str | None = None) -> str:
    base = ADMIN_URL.rsplit("/", 1)[0]
    if user is not None:
        scheme, rest = base.split("://", 1)
        host = rest.split("@", 1)[-1]
        base = f"{scheme}://{user}:{password}@{host}"
    return f"{base}/{name}"


def database_available() -> bool:
    try:
        with psycopg.connect(ADMIN_URL, connect_timeout=2):
            return True
    except psycopg.OperationalError:
        return False


def require_database() -> None:
    if not database_available():
        if os.environ.get("IDENTITY_REQUIRE_DB") == "1":
            pytest.fail(f"Test database unreachable at {ADMIN_URL}")
        pytest.skip("Postgres not reachable; run: docker compose -f dev/docker-compose.yml up -d")


def alembic(url: str, *args: str) -> None:
    from alembic import command
    from alembic.config import Config

    config = Config(str(IDENTITY_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(IDENTITY_DIR / "migrations"))
    config.cmd_opts = type("Opts", (), {"x": [f"url={url}"]})()  # pyright: ignore[reportAttributeAccessIssue]
    getattr(command, args[0])(config, *args[1:])


def create_database(prefix: str) -> str:
    name = f"{prefix}_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    return name


def drop_database(name: str) -> None:
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))


def ensure_login(database: str) -> None:
    """The service's login: NOINHERIT, member of identity_app only (README.md, "Database")."""
    with psycopg.connect(db_url(database), autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (LOGIN_ROLE,)).fetchone()
        if exists is None:
            conn.execute(
                sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
                    sql.Identifier(LOGIN_ROLE), sql.Literal(LOGIN_PASSWORD)
                )
            )
        conn.execute(sql.SQL("GRANT identity_app TO {}").format(sql.Identifier(LOGIN_ROLE)))
        conn.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(database), sql.Identifier(LOGIN_ROLE))
        )


@pytest.fixture(scope="session")
def database() -> Iterator[str]:
    """Name of a database migrated to head from empty."""
    require_database()
    name = create_database("identity_test")
    try:
        alembic(db_url(name), "upgrade", "head")
        ensure_login(name)
        yield name
    finally:
        drop_database(name)


@pytest.fixture(scope="session")
def owner_url(database: str) -> str:
    return db_url(database)


@pytest.fixture(scope="session")
def login_url(database: str) -> str:
    return db_url(database, user=LOGIN_ROLE, password=LOGIN_PASSWORD)


@pytest.fixture
async def owner(owner_url: str) -> AsyncIterator[psycopg.AsyncConnection]:
    async with await psycopg.AsyncConnection.connect(owner_url, autocommit=True) as conn:
        yield conn


# --------------------------------------------------------------------------- service-level fixtures


@pytest.fixture(scope="session")
def keys_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from identity.keys import generate_key

    directory = tmp_path_factory.mktemp("identity-keys")
    generate_key(directory)
    return directory


def make_settings(login_url: str, keys_dir: Path, **overrides: object) -> "Settings":
    from identity.config import Settings

    values: dict[str, object] = {
        "environment": "staging",
        "database_url": login_url,
        "issuer": "https://test.vetfab.ai/auth",
        "audience": "vetfab",
        "app_origins": "https://test.vetfab.ai",
        "keys_dir": keys_dir,
        **overrides,
    }
    return Settings(_env_file=None, **values)  # pyright: ignore[reportCallIssue, reportArgumentType]


@pytest.fixture(scope="session")
def settings(login_url: str, keys_dir: Path) -> "Settings":
    return make_settings(login_url, keys_dir)


@pytest.fixture(scope="session")
async def pool(login_url: str) -> AsyncIterator["AsyncConnectionPool"]:
    from identity.db import open_pool

    opened = await open_pool(login_url)
    try:
        yield opened
    finally:
        await opened.close()


@pytest.fixture
def make_user(owner_url: str) -> "Callable[..., User]":
    """Inserts an account as the owner would (operator action), optionally with a password."""
    from identity.passwords import hash_password
    from identity.store import User

    def make(
        email: str | None = None, *, status: str = "approved", password: str | None = None, name: str = "Test User"
    ) -> User:
        address = email or f"{uuid.uuid4().hex[:12]}@test.vetfab"
        hashed = hash_password(password) if password else None
        with psycopg.connect(owner_url, autocommit=True) as conn:
            row = conn.execute(
                """INSERT INTO public.users (email, display_name, status, password_hash)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (email) DO UPDATE SET display_name = EXCLUDED.display_name,
                     status = EXCLUDED.status, password_hash = EXCLUDED.password_hash
                   RETURNING id""",
                (address, name, status, hashed),
            ).fetchone()
        assert row is not None
        return User(id=row[0], email=address, display_name=name, status=status, password_hash=hashed)

    return make


# --------------------------------------------------------------------------- HTTP fixtures

ORIGIN = "https://test.vetfab.ai"
SAME_ORIGIN = {"origin": ORIGIN, "sec-fetch-site": "same-origin"}
PASSWORD = "correct horse battery"  # noqa: S105  # test fixture


@pytest.fixture
def clear_attempts(owner_url: str) -> None:
    """Rate-limit counters are keyed by client address, which every in-process test shares."""
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("DELETE FROM identity.signin_attempts")


def client_for(app: object) -> "httpx.AsyncClient":
    import httpx

    transport = httpx.ASGITransport(app=app)  # pyright: ignore[reportArgumentType]
    return httpx.AsyncClient(transport=transport, base_url=ORIGIN, follow_redirects=False)


def build_app(settings: "Settings", pool: "AsyncConnectionPool", keys_dir: Path) -> object:
    from identity.keys import KeyRing
    from identity.web.app import create_app

    return create_app(settings, pool=pool, keys=KeyRing.load(keys_dir))


@pytest.fixture(autouse=True)
def _clean_registry(request: pytest.FixtureRequest) -> Iterator[None]:
    """The registry and its tickets live in the shared test database and the environment seed never overwrites a row,
    so every database test starts from an empty registry and seeds what it needs."""
    if request.node.get_closest_marker("db") is None:
        yield
        return
    owner_url = request.getfixturevalue("owner_url")
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("DELETE FROM identity.handoff_tickets")
        conn.execute("DELETE FROM identity.services")
        conn.execute("DELETE FROM identity.developer_grants")
    yield
