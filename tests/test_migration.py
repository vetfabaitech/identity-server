"""Identity migration 0001: works on an empty database and on one holding the LMS stub, grants the service role only
what it needs, and downgrades without touching the base users table."""

from collections.abc import Iterator
from typing import Any, LiteralString, cast

import psycopg
import pytest
from psycopg import sql

from tests.conftest import (
    LMS_USERS_STUB,
    LOGIN_PASSWORD,
    LOGIN_ROLE,
    alembic,
    create_database,
    db_url,
    drop_database,
    ensure_login,
    require_database,
)

pytestmark = pytest.mark.db

IDENTITY_COLUMNS = {"password_hash", "email_verified_at", "last_login_at"}
BASE_COLUMNS = {"id", "email", "display_name", "status", "role", "created_at"}


@pytest.fixture
def scratch() -> Iterator[str]:
    require_database()
    name = create_database("identity_mig")
    try:
        yield name
    finally:
        drop_database(name)


def columns(url: str) -> set[str]:
    with psycopg.connect(url) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users'"
        ).fetchall()
    return {r[0] for r in rows}


def tables(url: str) -> set[str]:
    with psycopg.connect(url) as conn:
        rows = conn.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'identity'").fetchall()
    return {r[0] for r in rows}


def test_upgrade_on_an_empty_database_creates_the_users_table(scratch: str) -> None:
    alembic(db_url(scratch), "upgrade", "head")
    assert columns(db_url(scratch)) == BASE_COLUMNS | IDENTITY_COLUMNS
    assert tables(db_url(scratch)) >= {"refresh_tokens", "signin_attempts", "audit"}


def test_upgrade_keeps_rows_of_the_lms_stub(scratch: str) -> None:
    url = db_url(scratch)
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(cast(LiteralString, LMS_USERS_STUB.read_text()))
        conn.execute("INSERT INTO public.users (email, display_name, status) VALUES ('a@x.test', 'A', 'approved')")
    alembic(url, "upgrade", "head")
    assert columns(url) == BASE_COLUMNS | IDENTITY_COLUMNS
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT status FROM public.users WHERE email = 'a@x.test'").fetchone() == ("approved",)


def test_email_is_unique_regardless_of_case(scratch: str) -> None:
    url = db_url(scratch)
    alembic(url, "upgrade", "head")
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("INSERT INTO public.users (email, display_name) VALUES ('a@x.test', 'A')")
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute("INSERT INTO public.users (email, display_name) VALUES ('A@X.test', 'B')")


def test_downgrade_removes_identity_objects_but_keeps_users(scratch: str) -> None:
    url = db_url(scratch)
    alembic(url, "upgrade", "head")
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("INSERT INTO public.users (email, display_name) VALUES ('keep@x.test', 'Keep')")
    alembic(url, "downgrade", "base")
    assert columns(url) == BASE_COLUMNS
    assert tables(url) <= {"alembic_version"}
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT count(*) FROM public.users").fetchone() == (1,)
    alembic(url, "upgrade", "head")  # and back up again
    assert columns(url) == BASE_COLUMNS | IDENTITY_COLUMNS


def test_0005_adds_the_registry_and_rolls_back_cleanly(scratch: str) -> None:
    """The managed service registry: upgrade, data, rollback (which drops it and its audit rows), upgrade again."""
    url = db_url(scratch)
    alembic(url, "upgrade", "head")
    assert tables(url) >= {"services", "developer_grants"}
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(
            """INSERT INTO identity.services (id, display_name, environment, base_url, secret_sha256)
               VALUES ('svc', 'Svc', 'staging', 'https://svc.example', repeat('a', 64))"""
        )
        conn.execute("INSERT INTO identity.audit (action) VALUES ('service_created')")
        with pytest.raises(psycopg.errors.UniqueViolation):  # one registration per address
            conn.execute(
                """INSERT INTO identity.services (id, display_name, environment, base_url, secret_sha256)
                   VALUES ('svc2', 'Svc', 'staging', 'https://svc.example', repeat('b', 64))"""
            )
        with pytest.raises(psycopg.errors.CheckViolation):  # only a hash of 64 hex characters can be stored
            conn.execute(
                """INSERT INTO identity.services (id, display_name, environment, base_url, secret_sha256)
                   VALUES ('svc3', 'Svc', 'staging', 'https://other.example', 'plaintext-secret')"""
            )
    alembic(url, "downgrade", "0004")
    assert not tables(url) & {"services", "developer_grants"}
    assert tables(url) >= {"handoff_tickets", "audit"}
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT count(*) FROM identity.audit WHERE action = 'service_created'").fetchone() == (0,)
    alembic(url, "upgrade", "head")
    assert tables(url) >= {"services", "developer_grants"}


def test_the_service_role_can_register_and_disable_but_never_delete_a_service(database: str) -> None:
    with _as_login(database) as conn:
        conn.execute("SET ROLE identity_app")
        conn.execute(
            """INSERT INTO identity.services (id, display_name, environment, base_url, secret_sha256)
               VALUES ('roletest', 'Role', 'local', 'http://localhost:9', repeat('c', 64))"""
        )
        conn.execute("UPDATE identity.services SET status = 'disabled' WHERE id = 'roletest'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM identity.services WHERE id = 'roletest'")


def _as_login(database: str) -> psycopg.Connection[Any]:
    conn = psycopg.connect(db_url(database, user=LOGIN_ROLE, password=LOGIN_PASSWORD), autocommit=True)
    return conn


def test_the_service_role_reads_and_writes_its_tables(database: str) -> None:
    with _as_login(database) as conn:
        conn.execute("SET ROLE identity_app")
        uid = conn.execute(
            "INSERT INTO public.users (email, display_name) VALUES ('svc@x.test', 'Svc') RETURNING id"
        ).fetchone()
        assert uid is not None
        conn.execute("UPDATE public.users SET password_hash = 'h' WHERE id = %s", (uid[0],))
        conn.execute(
            """INSERT INTO identity.refresh_tokens (family_id, user_id, token_hash, expires_at)
               VALUES (gen_random_uuid(), %s, decode(repeat('ab', 32), 'hex'), now() + interval '1 day')""",
            (uid[0],),
        )
        conn.execute("INSERT INTO identity.signin_attempts (key, window_start, count) VALUES ('k', now(), 1)")
        conn.execute("INSERT INTO identity.audit (action, user_id) VALUES ('signin', %s)", (uid[0],))
        assert conn.execute("SELECT count(*) FROM public.users WHERE email = 'svc@x.test'").fetchone() == (1,)


def test_the_audit_log_is_append_only_for_the_service(database: str) -> None:
    with _as_login(database) as conn:
        conn.execute("SET ROLE identity_app")
        conn.execute("INSERT INTO identity.audit (action) VALUES ('signin')")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM identity.audit")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE identity.audit SET action = 'logout'")


def test_the_login_alone_has_no_access(database: str) -> None:
    """NOINHERIT: without SET ROLE identity_app the login can read nothing."""
    with _as_login(database) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("SELECT count(*) FROM public.users")


def test_a_role_outside_identity_app_cannot_read_users(scratch: str) -> None:
    url = db_url(scratch)
    alembic(url, "upgrade", "head")
    ensure_login(scratch)
    outsider = "identity_test_outsider"
    with psycopg.connect(url, autocommit=True) as conn:
        if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (outsider,)).fetchone() is None:
            conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(outsider)))
        conn.execute(sql.SQL("GRANT {} TO CURRENT_USER").format(sql.Identifier(outsider)))
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(outsider)))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT count(*) FROM public.users")


def test_every_identity_table_has_row_level_security(database: str) -> None:
    with psycopg.connect(db_url(database)) as conn:
        rows = conn.execute(
            """SELECT c.relname, c.relrowsecurity, (SELECT count(*) FROM pg_policies p
                                                     WHERE p.schemaname = n.nspname AND p.tablename = c.relname)
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind = 'r' AND ((n.nspname = 'identity' AND c.relname <> 'alembic_version')
                                           OR (n.nspname = 'public' AND c.relname = 'users'))"""
        ).fetchall()
    assert {r[0] for r in rows} == {
        "refresh_tokens",
        "signin_attempts",
        "audit",
        "oauth_accounts",
        "handoff_tickets",
        "services",
        "developer_grants",
        "user_versions",
        "user_events",
        "users",
    }
    for name, rls, policies in rows:
        assert rls, f"{name} has RLS disabled"
        assert policies >= 1, f"{name} has no policy"


def test_0002_creates_oauth_accounts_for_the_service(database: str) -> None:
    with _as_login(database) as conn:
        conn.execute("SET ROLE identity_app")
        row = conn.execute(
            "INSERT INTO public.users (email, display_name) VALUES ('oauth@x.test', 'O') RETURNING id"
        ).fetchone()
        assert row is not None
        conn.execute(
            "INSERT INTO identity.oauth_accounts (provider, provider_user_id, user_id, email_at_link) "
            "VALUES ('github', '42', %s, 'oauth@x.test')",
            (row[0],),
        )
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(
                "INSERT INTO identity.oauth_accounts (provider, provider_user_id, user_id) VALUES ('github', '42', %s)",
                (row[0],),
            )
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO identity.oauth_accounts (provider, provider_user_id, user_id) VALUES ('gitlab', '1', %s)",
                (row[0],),
            )
        for action in ("oauth_signin", "oauth_linked", "admin_bootstrapped"):
            conn.execute("INSERT INTO identity.audit (action) VALUES (%s)", (action,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE identity.oauth_accounts SET user_id = user_id")


def test_downgrade_to_0001_removes_oauth_accounts(scratch: str) -> None:
    url = db_url(scratch)
    alembic(url, "upgrade", "head")
    assert "oauth_accounts" in tables(url)
    alembic(url, "downgrade", "0001")
    assert "oauth_accounts" not in tables(url)
    with psycopg.connect(url, autocommit=True) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("INSERT INTO identity.audit (action) VALUES ('oauth_signin')")
    alembic(url, "upgrade", "head")
    assert "oauth_accounts" in tables(url)


# --------------------------------------------------------------------------- 0003: legacy IDE links (spec 2026-10-18 SI-5)

IDE_USERS = """
CREATE TABLE public.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_provider text,
  oauth_id text,
  username text UNIQUE,
  display_name text NOT NULL,
  email text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'pending',
  role text NOT NULL DEFAULT 'beta_user',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (oauth_provider, oauth_id)
);
"""


def test_0003_backfills_links_from_the_ide_users_table(scratch: str) -> None:
    """The IDE's users table (shared, SI-2) carries each account's sign-in provider; existing GitHub users must sign
    straight into their old account through the identity service."""
    url = db_url(scratch)
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(cast(LiteralString, IDE_USERS))
        conn.execute(
            """INSERT INTO public.users (oauth_provider, oauth_id, username, display_name, email, status) VALUES
               ('github', '1001', 'octo', 'Octo', 'Octo@X.test', 'approved'),
               ('google', 'g-7', 'gina', 'Gina', 'gina@x.test', 'pending'),
               ('password', 'p-1', 'pat', 'Pat', 'pat@x.test', 'approved'),
               (NULL, NULL, NULL, 'New', 'new@x.test', 'pending')"""
        )
    alembic(url, "upgrade", "head")
    with psycopg.connect(url) as conn:
        links = conn.execute(
            """SELECT a.provider, a.provider_user_id, u.username, a.email_at_link
                 FROM identity.oauth_accounts a JOIN public.users u ON u.id = a.user_id ORDER BY a.provider"""
        ).fetchall()
    assert links == [("github", "1001", "octo", "Octo@X.test"), ("google", "g-7", "gina", "gina@x.test")]


def test_0003_is_a_no_op_without_the_ide_columns(scratch: str) -> None:
    url = db_url(scratch)
    alembic(url, "upgrade", "head")
    assert "oauth_accounts" in tables(url)
    alembic(url, "downgrade", "0002")
    alembic(url, "upgrade", "head")


# --------------------------------------------------------------------------- 0006: the user feed (CONTRACT.md, "User feed")

FEED_TABLES = {"user_versions", "user_events"}
FEED_TRIGGERS = {"identity_user_event_insert", "identity_user_event_update", "identity_user_event_delete"}
FEED_FUNCTIONS = {"record_user_event", "purge_user_events"}


def feed_objects(url: str) -> tuple[set[str], set[str], set[str]]:
    """(identity tables of the feed, triggers on public.users, identity functions of the feed) that exist."""
    with psycopg.connect(url) as conn:
        triggers = conn.execute(
            "SELECT tgname FROM pg_trigger WHERE tgrelid = 'public.users'::regclass AND NOT tgisinternal"
        ).fetchall()
        functions = conn.execute(
            """SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'identity'"""
        ).fetchall()
    return tables(url) & FEED_TABLES, {r[0] for r in triggers}, {r[0] for r in functions} & FEED_FUNCTIONS


def test_0006_backfills_every_user_at_version_1_and_rolls_back_cleanly(scratch: str) -> None:
    url = db_url(scratch)
    alembic(url, "upgrade", "0005")
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("INSERT INTO public.users (email, display_name) VALUES ('a@x.test', 'A'), ('b@x.test', 'B')")
    alembic(url, "upgrade", "head")
    assert feed_objects(url) == (FEED_TABLES, FEED_TRIGGERS, FEED_FUNCTIONS)
    with psycopg.connect(url, autocommit=True) as conn:
        assert conn.execute(
            """SELECT count(*) FROM public.users u JOIN identity.user_versions v ON v.user_id = u.id
                WHERE v.version = 1"""
        ).fetchone() == (2,)
        assert conn.execute("SELECT count(*) FROM identity.user_events").fetchone() == (0,)  # a backfill is no event
        conn.execute("UPDATE public.users SET status = 'approved' WHERE email = 'a@x.test'")
        assert conn.execute("SELECT version, type FROM identity.user_events").fetchall() == [(2, "user.updated")]
    alembic(url, "downgrade", "0005")
    assert feed_objects(url) == (set(), set(), set())
    with psycopg.connect(url, autocommit=True) as conn:  # the users table works exactly as before
        conn.execute("UPDATE public.users SET display_name = 'A2' WHERE email = 'a@x.test'")
        conn.execute("DELETE FROM public.users WHERE email = 'b@x.test'")
        conn.execute("INSERT INTO public.users (email, display_name) VALUES ('c@x.test', 'C')")
    alembic(url, "upgrade", "head")
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT count(*), min(version), max(version) FROM identity.user_versions").fetchone() == (
            2,
            1,
            1,
        )


def test_0006_records_changes_on_the_ide_users_table(scratch: str) -> None:
    """The IDE's own table (shared, SI-2): its profile columns change silently, its admin console's status changes
    are events."""
    url = db_url(scratch)
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(cast(LiteralString, IDE_USERS))
        conn.execute(
            """INSERT INTO public.users (oauth_provider, oauth_id, username, display_name, email, status)
               VALUES ('github', '1001', 'octo', 'Octo', 'octo@x.test', 'pending')"""
        )
    alembic(url, "upgrade", "head")
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("UPDATE public.users SET username = 'octo2', oauth_id = '1002' WHERE email = 'octo@x.test'")
        conn.execute("UPDATE public.users SET status = 'approved', role = 'admin' WHERE email = 'octo@x.test'")
        rows = conn.execute("SELECT version, type, email, display_name, status FROM identity.user_events").fetchall()
    assert rows == [(2, "user.updated", "octo@x.test", "Octo", "approved")]


def test_the_service_role_only_reads_the_feed_and_purges_through_the_function(database: str) -> None:
    with _as_login(database) as conn:
        conn.execute("SET ROLE identity_app")
        conn.execute("SELECT count(*) FROM identity.user_events")
        conn.execute("SELECT count(*) FROM identity.user_versions")
        conn.execute("SELECT identity.purge_user_events(30, 1)")
        for statement in (
            "INSERT INTO identity.user_events (user_id, version, type) VALUES (gen_random_uuid(), 1, 'user.created')",
            "UPDATE identity.user_events SET version = version + 1",
            "DELETE FROM identity.user_events",
            "INSERT INTO identity.user_versions (user_id, version) VALUES (gen_random_uuid(), 1)",
            "UPDATE identity.user_versions SET version = version + 1",
            "DELETE FROM identity.user_versions",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(cast(LiteralString, statement))


def test_the_feed_functions_are_definer_functions_with_a_fixed_search_path(database: str) -> None:
    with psycopg.connect(db_url(database)) as conn:
        rows = conn.execute(
            """SELECT p.proname, p.prosecdef, p.proconfig, has_function_privilege('public', p.oid, 'EXECUTE'),
                      has_function_privilege('identity_app', p.oid, 'EXECUTE')
                 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'identity' AND p.proname IN ('record_user_event', 'purge_user_events')"""
        ).fetchall()
    found = {name: (definer, config, public, app) for name, definer, config, public, app in rows}
    assert found == {
        "record_user_event": (True, ["search_path=pg_catalog, pg_temp"], False, False),
        "purge_user_events": (True, ["search_path=pg_catalog, pg_temp"], False, True),
    }
