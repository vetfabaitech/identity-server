"""Account lookups, the sign-in rate limit and the audit log."""

from collections.abc import Callable

import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from identity import store
from identity.store import User

pytestmark = pytest.mark.db


async def test_email_lookup_ignores_case_and_surrounding_spaces(
    pool: AsyncConnectionPool, make_user: Callable[..., User]
) -> None:
    user = make_user("casey@dev.vetfab.local")
    async with pool.connection() as conn:
        found = await store.find_user_by_email(conn, "  Casey@Dev.Vetfab.Local ")
        missing = await store.find_user_by_email(conn, "nobody@dev.vetfab.local")
    assert found is not None and found.id == user.id
    assert missing is None


async def test_list_users_by_emails_keeps_the_requested_order(
    pool: AsyncConnectionPool, make_user: Callable[..., User]
) -> None:
    b = make_user("order-b@dev.vetfab.local")
    a = make_user("order-a@dev.vetfab.local")
    async with pool.connection() as conn:
        users = await store.list_users_by_emails(
            conn, ["order-b@dev.vetfab.local", "absent@dev.vetfab.local", "order-a@dev.vetfab.local"]
        )
    assert [u.id for u in users] == [b.id, a.id]


async def test_create_user_stores_a_normalised_email(pool: AsyncConnectionPool) -> None:
    async with pool.connection() as conn:
        user = await store.create_user(conn, "  New.Person@Dev.Vetfab.Local ", "New Person", "approved")
    assert user.email == "new.person@dev.vetfab.local"
    assert user.status == "approved"


async def test_rate_limit_counts_failures_per_key_inside_the_window(pool: AsyncConnectionPool, owner_url: str) -> None:
    keys = ["email:limit@dev.vetfab.local", "ip:203.0.113.9"]
    async with pool.connection() as conn:
        for _ in range(3):
            assert not await store.rate_limited(conn, keys, limit=3, window_seconds=600)
            await store.record_failure(conn, keys, window_seconds=600)
        assert await store.rate_limited(conn, keys, limit=3, window_seconds=600)
        assert await store.rate_limited(conn, ["ip:203.0.113.9"], limit=3, window_seconds=600)
        assert not await store.rate_limited(conn, ["ip:198.51.100.1"], limit=3, window_seconds=600)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        owner.execute(
            "UPDATE identity.signin_attempts SET window_start = now() - interval '11 minutes' WHERE key = ANY(%s)",
            (keys,),
        )
    async with pool.connection() as conn:
        assert not await store.rate_limited(conn, keys, limit=3, window_seconds=600), "an old window no longer counts"
        await store.record_failure(conn, keys, window_seconds=600)
        assert not await store.rate_limited(conn, keys, limit=3, window_seconds=600), "the window restarted at 1"
        await store.clear_failures(conn, keys[0])
    with psycopg.connect(owner_url) as owner:
        left = owner.execute("SELECT key FROM identity.signin_attempts WHERE key = ANY(%s)", (keys,)).fetchall()
    assert [r[0] for r in left] == ["ip:203.0.113.9"]


async def test_audit_rows_are_written(
    pool: AsyncConnectionPool, make_user: Callable[..., User], owner_url: str
) -> None:
    user = make_user()
    async with pool.connection() as conn:
        await store.audit(conn, "signin", user_id=user.id, ip="203.0.113.9", user_agent="x" * 2000, metadata={"a": 1})
    with psycopg.connect(owner_url) as owner:
        row = owner.execute(
            "SELECT action, ip, char_length(user_agent), metadata FROM identity.audit WHERE user_id = %s", (user.id,)
        ).fetchone()
    assert row == ("signin", "203.0.113.9", 512, {"a": 1})


async def test_status_and_password_updates(
    pool: AsyncConnectionPool, make_user: Callable[..., User], owner_url: str
) -> None:
    user = make_user()
    async with pool.connection() as conn:
        await store.set_status(conn, user.id, "suspended")
        await store.set_password(conn, user.id, "argon-hash")
        await store.touch_login(conn, user.id)
        refreshed = await store.get_user(conn, user.id)
    assert refreshed is not None
    assert refreshed.status == "suspended" and refreshed.password_hash == "argon-hash"
    with psycopg.connect(owner_url) as owner:
        last = owner.execute("SELECT last_login_at IS NOT NULL FROM public.users WHERE id = %s", (user.id,)).fetchone()
    assert last == (True,)


async def test_link_and_find_by_oauth(pool: AsyncConnectionPool, make_user: Callable[..., User]) -> None:
    user = make_user()
    async with pool.connection() as conn:
        await store.link_oauth(conn, user.id, "github", "1001", user.email)
        found = await store.find_user_by_oauth(conn, "github", "1001")
        other_provider = await store.find_user_by_oauth(conn, "google", "1001")
        unknown = await store.find_user_by_oauth(conn, "github", "9999")
    assert found is not None and found.id == user.id and found.role == "beta_user"
    assert other_provider is None and unknown is None


async def test_create_user_with_role(pool: AsyncConnectionPool) -> None:
    async with pool.connection() as conn:
        user = await store.create_user(conn, "role-admin@dev.vetfab.local", "Ada", "approved", role="admin")
        default = await store.create_user(conn, "role-default@dev.vetfab.local", "Bea", "pending")
    assert user.role == "admin"
    assert default.role == "beta_user"


async def test_promote_admin_sets_role_and_status(pool: AsyncConnectionPool, make_user: Callable[..., User]) -> None:
    user = make_user(status="pending")
    async with pool.connection() as conn:
        await store.promote_admin(conn, user.id)
        promoted = await store.get_user(conn, user.id)
    assert promoted is not None
    assert (promoted.role, promoted.status) == ("admin", "approved")
