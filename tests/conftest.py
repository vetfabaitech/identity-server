"""Test harness for the identity service.

* A throwaway database per session (`identity_test_<hex>`) on the local compose Postgres (or IDENTITY_TEST_ADMIN_URL),
  migrated to head on an empty database, the way the test box creates it.
* `login_url`: a dedicated NOINHERIT login that is a member of `identity_app` only, so every DB test runs with the
  privileges the deployed service has, never the owner's.
* Without a reachable database the `db` tests skip, unless IDENTITY_REQUIRE_DB=1 (CI).
"""

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import psycopg
import pytest
from psycopg import sql

IDENTITY_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = IDENTITY_DIR.parent.parent
LMS_USERS_STUB = REPO_DIR / "infra/local/postgres-init/01-identity-users-stub.sql"

ADMIN_URL = os.environ.get(
    "IDENTITY_TEST_ADMIN_URL",
    os.environ.get("LMS_TEST_ADMIN_URL", "postgresql://lms:lms-local-only@127.0.0.1:54329/lms"),
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
        pytest.skip("Postgres not reachable; run: docker compose -f infra/local/docker-compose.yml up -d")


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
    """The service's login: NOINHERIT, member of identity_app only (docs/operations/runbooks/database-roles.md)."""
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
