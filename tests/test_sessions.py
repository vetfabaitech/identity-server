"""Refresh sessions: rotate on every use, tolerate two tabs renewing at once, revoke the family on real reuse."""

from collections.abc import Callable

import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from identity import sessions
from identity.config import Settings
from identity.sessions import Issued, Rejected, token_hash
from identity.store import User

pytestmark = pytest.mark.db


def _owner_exec(owner_url: str, query: str, *params: object) -> None:
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute(query, params)  # pyright: ignore[reportArgumentType]


async def _issue(pool: AsyncConnectionPool, user: User, settings: Settings) -> str:
    async with pool.connection() as conn:
        return await sessions.issue(conn, user, settings, "pytest")


async def _renew(pool: AsyncConnectionPool, raw: str, settings: Settings) -> sessions.Renewal:
    async with pool.connection() as conn:
        return await sessions.renew(conn, raw, settings, "pytest")


async def test_renew_rotates_the_token(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User]
) -> None:
    user = make_user()
    first = await _issue(pool, user, settings)
    renewal = await _renew(pool, first, settings)
    assert isinstance(renewal, Issued)
    assert renewal.user.id == user.id
    assert renewal.refresh_token is not None and renewal.refresh_token != first
    second = await _renew(pool, renewal.refresh_token, settings)
    assert isinstance(second, Issued) and second.refresh_token is not None


async def test_two_tabs_renewing_at_once_both_stay_signed_in(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User]
) -> None:
    user = make_user()
    first = await _issue(pool, user, settings)
    winner = await _renew(pool, first, settings)
    loser = await _renew(pool, first, settings)
    assert isinstance(winner, Issued) and winner.refresh_token is not None
    assert loser == Issued(user=winner.user, refresh_token=None), "inside the grace window: a token, no new cookie"
    still = await _renew(pool, winner.refresh_token, settings)
    assert isinstance(still, Issued), "the winner's token must still work"


async def test_reuse_after_the_grace_window_revokes_the_whole_session(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User], owner_url: str
) -> None:
    user = make_user()
    first = await _issue(pool, user, settings)
    renewal = await _renew(pool, first, settings)
    assert isinstance(renewal, Issued) and renewal.refresh_token is not None
    _owner_exec(
        owner_url,
        "UPDATE identity.refresh_tokens SET rotated_at = now() - interval '5 minutes' WHERE token_hash = %s",
        token_hash(first),
    )
    assert await _renew(pool, first, settings) == Rejected("reuse")
    assert await _renew(pool, renewal.refresh_token, settings) == Rejected("revoked")


async def test_expired_and_unknown_tokens(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User], owner_url: str
) -> None:
    user = make_user()
    raw = await _issue(pool, user, settings)
    _owner_exec(
        owner_url,
        "UPDATE identity.refresh_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = %s",
        token_hash(raw),
    )
    assert await _renew(pool, raw, settings) == Rejected("expired")
    assert await _renew(pool, "x" * 43, settings) == Rejected("unknown")
    assert await _renew(pool, "", settings) == Rejected("unknown")


@pytest.mark.parametrize("status", ["suspended", "rejected"])
async def test_an_inactive_account_cannot_renew(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User], owner_url: str, status: str
) -> None:
    user = make_user()
    raw = await _issue(pool, user, settings)
    _owner_exec(owner_url, "UPDATE public.users SET status = %s WHERE id = %s", status, user.id)
    assert await _renew(pool, raw, settings) == Rejected("inactive")
    _owner_exec(owner_url, "UPDATE public.users SET status = 'approved' WHERE id = %s", user.id)
    assert await _renew(pool, raw, settings) == Rejected("revoked"), "the session stays revoked after reactivation"


async def test_pending_accounts_renew(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User]
) -> None:
    user = make_user(status="pending")
    raw = await _issue(pool, user, settings)
    assert isinstance(await _renew(pool, raw, settings), Issued)


async def test_revoke_ends_the_session(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User]
) -> None:
    user = make_user()
    raw = await _issue(pool, user, settings)
    async with pool.connection() as conn:
        assert await sessions.revoke(conn, raw, "logout") == user.id
        assert await sessions.revoke(conn, "x" * 43, "logout") is None
    assert await _renew(pool, raw, settings) == Rejected("revoked")


async def test_revoke_user_ends_every_session(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User]
) -> None:
    user = make_user()
    tokens = [await _issue(pool, user, settings) for _ in range(3)]
    async with pool.connection() as conn:
        assert await sessions.revoke_user(conn, user.id, "admin") == 3
    for raw in tokens:
        assert await _renew(pool, raw, settings) == Rejected("revoked")


async def test_only_the_hash_is_stored(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User], owner_url: str
) -> None:
    user = make_user()
    raw = await _issue(pool, user, settings)
    with psycopg.connect(owner_url) as conn:
        stored = conn.execute(
            "SELECT token_hash FROM identity.refresh_tokens WHERE user_id = %s", (user.id,)
        ).fetchone()
    assert stored is not None and bytes(stored[0]) == token_hash(raw)
    assert raw.encode() not in bytes(stored[0])
