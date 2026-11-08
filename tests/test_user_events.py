"""Change capture for the user feed (migration 0006): the trigger on public.users, its ordering lock and the purge.

Every test here works relative to the current head: the session database is shared, so other tests' events exist.
"""

import asyncio
import importlib.util
import random
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
import pytest
from psycopg import sql
from psycopg_pool import AsyncConnectionPool

from identity import store, user_feed
from identity.cli import main
from identity.store import User
from tests.conftest import IDENTITY_DIR, make_settings

pytestmark = pytest.mark.db

IDE_ROLE = "identity_test_ide_service_role"


@dataclass(frozen=True)
class Event:
    seq: int
    user_id: UUID
    version: int
    type: str
    email: str | None
    display_name: str | None
    status: str | None


def head(conn: psycopg.Connection[Any]) -> int:
    row = conn.execute("SELECT coalesce(max(seq), 0) FROM identity.user_events").fetchone()
    assert row is not None
    return row[0]


def since(conn: psycopg.Connection[Any], seq: int) -> list[Event]:
    rows = conn.execute(
        """SELECT seq, user_id, version, type, email, display_name, status FROM identity.user_events
            WHERE seq > %s ORDER BY seq""",
        (seq,),
    ).fetchall()
    return [Event(*row) for row in rows]


def version(conn: psycopg.Connection[Any], user_id: UUID) -> int | None:
    row = conn.execute("SELECT version FROM identity.user_versions WHERE user_id = %s", (user_id,)).fetchone()
    return row[0] if row else None


@pytest.fixture
def owner_conn(owner_url: str) -> Iterator[psycopg.Connection[Any]]:
    with psycopg.connect(owner_url, autocommit=True) as conn:
        yield conn


def new_user(conn: psycopg.Connection[Any], name: str = "Ada", status: str = "pending") -> UUID:
    email = f"{uuid.uuid4().hex[:12]}@feed.test"
    row = conn.execute(
        "INSERT INTO public.users (email, display_name, status) VALUES (%s, %s, %s) RETURNING id", (email, name, status)
    ).fetchone()
    assert row is not None
    return row[0]


# --------------------------------------------------------------------------- what the trigger records


def test_a_new_user_starts_at_version_1_with_a_created_event(owner_conn: psycopg.Connection[Any]) -> None:
    base = head(owner_conn)
    uid = new_user(owner_conn, "Ada", "pending")
    [event] = since(owner_conn, base)
    email = owner_conn.execute("SELECT email FROM public.users WHERE id = %s", (uid,)).fetchone()
    assert email is not None
    assert (event.user_id, event.version, event.type) == (uid, 1, "user.created")
    assert (event.email, event.display_name, event.status) == (email[0], "Ada", "pending")
    assert version(owner_conn, uid) == 1


def test_each_change_to_email_name_or_status_is_one_event_and_one_version(
    owner_conn: psycopg.Connection[Any],
) -> None:
    uid = new_user(owner_conn)
    base = head(owner_conn)
    owner_conn.execute(
        "UPDATE public.users SET email = %s, display_name = 'Grace', status = 'approved' WHERE id = %s",
        (f"{uid.hex[:12]}@moved.test", uid),
    )
    owner_conn.execute("UPDATE public.users SET status = 'suspended' WHERE id = %s", (uid,))
    owner_conn.execute("UPDATE public.users SET display_name = 'Grace H' WHERE id = %s", (uid,))
    events = since(owner_conn, base)
    assert [(e.version, e.type, e.display_name, e.status) for e in events] == [
        (2, "user.updated", "Grace", "approved"),
        (3, "user.updated", "Grace", "suspended"),
        (4, "user.updated", "Grace H", "suspended"),
    ]
    assert all(e.email == f"{uid.hex[:12]}@moved.test" for e in events)  # each event is the whole snapshot
    assert version(owner_conn, uid) == 4


def test_an_update_that_changes_nothing_emits_nothing(owner_conn: psycopg.Connection[Any]) -> None:
    uid = new_user(owner_conn, "Ada", "approved")
    base = head(owner_conn)
    owner_conn.execute(
        "UPDATE public.users SET email = email, display_name = 'Ada', status = 'approved' WHERE id = %s", (uid,)
    )
    assert since(owner_conn, base) == []
    assert version(owner_conn, uid) == 1


def test_other_columns_emit_nothing(owner_conn: psycopg.Connection[Any]) -> None:
    uid = new_user(owner_conn)
    base = head(owner_conn)
    for assignment in (
        "password_hash = 'argon2-hash'",
        "last_login_at = now()",
        "email_verified_at = now()",
        "role = 'admin'",
        "created_at = now()",
    ):
        owner_conn.execute(
            sql.SQL("UPDATE public.users SET {} WHERE id = %s").format(sql.SQL(assignment)),  # pyright: ignore[reportArgumentType]
            (uid,),
        )
    assert since(owner_conn, base) == []
    assert version(owner_conn, uid) == 1


def test_a_delete_bumps_the_version_and_records_no_personal_data(owner_conn: psycopg.Connection[Any]) -> None:
    uid = new_user(owner_conn)
    owner_conn.execute("UPDATE public.users SET status = 'approved' WHERE id = %s", (uid,))
    base = head(owner_conn)
    owner_conn.execute("DELETE FROM public.users WHERE id = %s", (uid,))
    [event] = since(owner_conn, base)
    assert (event.user_id, event.version, event.type) == (uid, 3, "user.deleted")
    assert (event.email, event.display_name, event.status) == (None, None, None)
    assert version(owner_conn, uid) == 3  # outlives the user: no foreign key


def test_an_id_that_comes_back_keeps_counting(owner_conn: psycopg.Connection[Any]) -> None:
    uid = new_user(owner_conn)
    owner_conn.execute("DELETE FROM public.users WHERE id = %s", (uid,))
    base = head(owner_conn)
    owner_conn.execute(
        "INSERT INTO public.users (id, email, display_name) VALUES (%s, %s, 'Back')", (uid, f"{uid.hex}@back.test")
    )
    [event] = since(owner_conn, base)
    assert (event.version, event.type, event.display_name) == (3, "user.created", "Back")


def test_a_user_without_a_version_row_counts_as_version_1(owner_conn: psycopg.Connection[Any]) -> None:
    """A row written while the triggers were disabled has no version; its next change is version 2."""
    uid = new_user(owner_conn)
    owner_conn.execute("DELETE FROM identity.user_versions WHERE user_id = %s", (uid,))
    base = head(owner_conn)
    owner_conn.execute("UPDATE public.users SET display_name = 'Later' WHERE id = %s", (uid,))
    [event] = since(owner_conn, base)
    assert (event.version, event.type) == (2, "user.updated")


def test_a_rolled_back_write_leaves_no_event(owner_url: str, owner_conn: psycopg.Connection[Any]) -> None:
    uid = new_user(owner_conn)
    base = head(owner_conn)
    with psycopg.connect(owner_url) as conn:
        conn.execute("UPDATE public.users SET display_name = 'Never' WHERE id = %s", (uid,))
        conn.rollback()
    assert since(owner_conn, base) == []
    assert version(owner_conn, uid) == 1


def test_a_failing_write_is_not_blocked_or_changed_by_the_trigger(owner_conn: psycopg.Connection[Any]) -> None:
    """The trigger fires after the row is written, so the writer's own errors (a duplicate email) come first."""
    uid = new_user(owner_conn)
    email = owner_conn.execute("SELECT email FROM public.users WHERE id = %s", (uid,)).fetchone()
    assert email is not None
    base = head(owner_conn)
    with pytest.raises(psycopg.errors.UniqueViolation):
        owner_conn.execute("INSERT INTO public.users (email, display_name) VALUES (%s, 'Dup')", (email[0],))
    assert since(owner_conn, base) == []


# --------------------------------------------------------------------------- whoever writes


@pytest.fixture
def ide_role(owner_url: str) -> str:
    """Stands in for the IDE's Supabase `service_role`: BYPASSRLS, privileges on public.users and nothing in
    `identity`, not even USAGE on the schema."""
    with psycopg.connect(owner_url, autocommit=True) as conn:
        if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (IDE_ROLE,)).fetchone() is None:
            conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN BYPASSRLS").format(sql.Identifier(IDE_ROLE)))
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(IDE_ROLE)))
        conn.execute(
            sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO {}").format(sql.Identifier(IDE_ROLE))
        )
        assert conn.execute("SELECT has_schema_privilege(%s, 'identity', 'USAGE')", (IDE_ROLE,)).fetchone() == (False,)
    return IDE_ROLE


def test_a_write_by_a_role_with_no_access_to_identity_is_still_recorded(
    owner_conn: psycopg.Connection[Any], ide_role: str
) -> None:
    base = head(owner_conn)
    owner_conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(ide_role)))
    try:
        row = owner_conn.execute(
            "INSERT INTO public.users (email, display_name) VALUES (%s, 'Ide') RETURNING id",
            (f"{uuid.uuid4().hex[:12]}@ide.test",),
        ).fetchone()
        assert row is not None
        uid = row[0]
        owner_conn.execute("UPDATE public.users SET status = 'approved' WHERE id = %s", (uid,))
        owner_conn.execute("UPDATE public.users SET role = 'admin' WHERE id = %s", (uid,))
        owner_conn.execute("DELETE FROM public.users WHERE id = %s", (uid,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner_conn.execute("SELECT count(*) FROM identity.user_events")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            owner_conn.execute("SELECT identity.purge_user_events(30, 1)")
    finally:
        owner_conn.execute("RESET ROLE")
    events = since(owner_conn, base)
    assert [(e.user_id, e.version, e.type) for e in events] == [
        (uid, 1, "user.created"),
        (uid, 2, "user.updated"),
        (uid, 3, "user.deleted"),
    ]


async def test_the_services_own_writes_are_recorded(pool: AsyncConnectionPool, owner_url: str) -> None:
    """identity_app has no write privilege on either table: the definer trigger records its changes."""
    with psycopg.connect(owner_url) as conn:
        base = head(conn)
    async with pool.connection() as conn:
        user = await store.create_user(conn, f"{uuid.uuid4().hex[:12]}@svc.test", "Svc", "pending")
        await store.set_status(conn, user.id, "approved")
        await store.touch_login(conn, user.id)
        await store.set_password(conn, user.id, "argon2-hash")
        await store.promote_admin(conn, user.id)  # role changes, status is already approved
    with psycopg.connect(owner_url) as conn:
        events = since(conn, base)
    assert [(e.user_id, e.version, e.type, e.status) for e in events] == [
        (user.id, 1, "user.created", "pending"),
        (user.id, 2, "user.updated", "approved"),
    ]


# --------------------------------------------------------------------------- ordering (CONTRACT.md: events become visible in seq order)


async def _head(conn: psycopg.AsyncConnection[Any]) -> int:
    row = await (await conn.execute("SELECT coalesce(max(seq), 0) FROM identity.user_events")).fetchone()
    assert row is not None
    return row[0]


async def _since(conn: psycopg.AsyncConnection[Any], seq: int) -> list[tuple[int, UUID]]:
    cur = await conn.execute("SELECT seq, user_id FROM identity.user_events WHERE seq > %s ORDER BY seq", (seq,))
    return [(row[0], row[1]) for row in await cur.fetchall()]


async def _wait_for_advisory_lock(observer: psycopg.AsyncConnection[Any], pid: int) -> None:
    for _ in range(500):
        row = await (
            await observer.execute("SELECT wait_event_type, wait_event FROM pg_stat_activity WHERE pid = %s", (pid,))
        ).fetchone()
        if row == ("Lock", "advisory"):
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the second writer never waited for the user-events lock")


def test_the_lock_key_is_the_documented_one() -> None:
    path = IDENTITY_DIR / "migrations/versions/0006_user_feed.py"
    spec = importlib.util.spec_from_file_location("migration_0006", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.USER_EVENTS_LOCK == user_feed.USER_EVENTS_LOCK == 5279438479318730070
    assert user_feed.USER_EVENTS_LOCK.to_bytes(8, "big") == b"IDUSEREV"
    assert f"pg_advisory_xact_lock({user_feed.USER_EVENTS_LOCK})" in module.UPGRADE_SQL


async def test_a_later_write_cannot_become_visible_before_an_earlier_uncommitted_one(
    owner_url: str, make_user: Callable[..., User]
) -> None:
    """The first writer holds its transaction open after writing; the second's event must not be visible (it is
    not even allocated: the second waits for the lock) until the first commits, and seq order is commit order."""
    first_user, second_user = make_user(), make_user()
    async with (
        await psycopg.AsyncConnection.connect(owner_url) as first,
        await psycopg.AsyncConnection.connect(owner_url) as second,
        await psycopg.AsyncConnection.connect(owner_url, autocommit=True) as observer,
    ):
        base = await _head(observer)
        await first.execute("UPDATE public.users SET display_name = 'first' WHERE id = %s", (first_user.id,))
        lock = await (
            await observer.execute(
                """SELECT granted FROM pg_locks
                    WHERE locktype = 'advisory' AND pid = %s AND objsubid = 1
                      AND ((classid::bigint << 32) | objid::bigint) = %s""",
                (first.info.backend_pid, user_feed.USER_EVENTS_LOCK),
            )
        ).fetchone()
        assert lock == (True,), "the trigger holds the documented advisory lock until commit"

        commits: list[str] = []

        async def second_writer() -> None:
            await second.execute("UPDATE public.users SET display_name = 'second' WHERE id = %s", (second_user.id,))
            await second.commit()
            commits.append("second")

        task = asyncio.create_task(second_writer())
        await _wait_for_advisory_lock(observer, second.info.backend_pid)
        assert await _since(observer, base) == []  # neither event is visible: one uncommitted, one not yet written
        await asyncio.sleep(0.1)
        assert await _since(observer, base) == [] and not task.done()
        await first.commit()
        commits.append("first")
        await asyncio.wait_for(task, 10)
        seen = await _since(observer, base)
    assert commits == ["first", "second"]
    assert [user for _, user in seen] == [first_user.id, second_user.id]
    assert seen[0][0] < seen[1][0]


async def test_concurrent_writers_only_ever_expose_a_prefix_of_the_final_order(
    owner_url: str, make_user: Callable[..., User]
) -> None:
    """Eight writers commit at random moments while a reader polls: every read is a prefix of the final event list,
    so a consumer that moves its cursor to the last seq it saw can never skip an event committed later."""
    users = [make_user() for _ in range(8)]
    rounds = 3
    async with await psycopg.AsyncConnection.connect(owner_url, autocommit=True) as observer:
        base = await _head(observer)
        observations: list[list[tuple[int, UUID]]] = []
        finished = asyncio.Event()

        async def writer(index: int, user: User) -> None:
            async with await psycopg.AsyncConnection.connect(owner_url) as conn:
                for round_ in range(rounds):
                    await asyncio.sleep(random.uniform(0, 0.01))
                    await conn.execute(
                        "UPDATE public.users SET display_name = %s WHERE id = %s", (f"w{index}-{round_}", user.id)
                    )
                    await asyncio.sleep(random.uniform(0, 0.02))  # hold the transaction open a while
                    await conn.commit()

        async def reader() -> None:
            while not finished.is_set():
                observations.append(await _since(observer, base))
                await asyncio.sleep(0)

        polling = asyncio.create_task(reader())
        await asyncio.gather(*(writer(i, u) for i, u in enumerate(users)))
        finished.set()
        await polling
        final = await _since(observer, base)
    assert len(final) == len(users) * rounds
    assert len(observations) > 10
    for seen in observations:
        assert seen == final[: len(seen)]


# --------------------------------------------------------------------------- retention


def age(conn: psycopg.Connection[Any], through: int, days: int) -> None:
    conn.execute(
        "UPDATE identity.user_events SET occurred_at = now() - make_interval(days => %s) WHERE seq <= %s",
        (days, through),
    )


def bounds(conn: psycopg.Connection[Any]) -> tuple[int | None, int | None]:
    row = conn.execute("SELECT min(seq), max(seq) FROM identity.user_events").fetchone()
    assert row is not None
    return row[0], row[1]


def purge(conn: psycopg.Connection[Any], days: int, max_rows: int = 1000) -> int:
    row = conn.execute("SELECT identity.purge_user_events(%s, %s)", (days, max_rows)).fetchone()
    assert row is not None
    return row[0]


def test_purge_removes_expired_events_as_a_prefix(owner_conn: psycopg.Connection[Any]) -> None:
    base = head(owner_conn)
    for _ in range(4):
        new_user(owner_conn)
    events = since(owner_conn, base)
    expired_through = events[1].seq
    age(owner_conn, expired_through, 40)
    assert purge(owner_conn, 30) >= 2
    assert bounds(owner_conn) == (events[2].seq, events[3].seq)
    assert purge(owner_conn, 30) == 0  # nothing left past the retention


def test_purge_never_removes_the_newest_event(owner_conn: psycopg.Connection[Any]) -> None:
    new_user(owner_conn)
    newest = head(owner_conn)
    age(owner_conn, newest, 40)
    purge(owner_conn, 30)
    assert bounds(owner_conn) == (newest, newest)  # max(seq) stays the head


def test_purge_keeps_at_least_seven_days_whatever_it_is_asked(owner_conn: psycopg.Connection[Any]) -> None:
    for _ in range(3):
        new_user(owner_conn)
    newest = head(owner_conn)
    age(owner_conn, newest - 1, 5)
    assert purge(owner_conn, 1) == 0
    age(owner_conn, newest - 1, 8)
    assert purge(owner_conn, 1) >= 2
    assert bounds(owner_conn) == (newest, newest)


def test_purge_is_bounded(owner_conn: psycopg.Connection[Any]) -> None:
    for _ in range(5):
        new_user(owner_conn)
    newest = head(owner_conn)
    age(owner_conn, newest, 40)
    retained = [e.seq for e in since(owner_conn, 0)]
    assert len(retained) >= 5
    assert purge(owner_conn, 30, max_rows=2) == 2
    assert bounds(owner_conn) == (retained[2], newest)  # the two oldest, ties broken by seq
    while purge(owner_conn, 30, max_rows=2):
        pass
    assert bounds(owner_conn) == (newest, newest)


def test_identity_admin_purges_past_the_retention(
    capsys: pytest.CaptureFixture[str], owner_conn: psycopg.Connection[Any], login_url: str, tmp_path: Path
) -> None:
    for _ in range(3):
        new_user(owner_conn)
    newest = head(owner_conn)
    age(owner_conn, newest - 1, 31)
    settings = make_settings(login_url, tmp_path / "keys")
    assert main(["purge-user-events"], settings=settings) == 0
    out = capsys.readouterr().out
    assert "older than 30 days" in out and not out.startswith("Purged 0 ")
    assert bounds(owner_conn) == (newest, newest)
    assert main(["purge-user-events"], settings=settings) == 0
    assert capsys.readouterr().out.startswith("Purged 0 ")
