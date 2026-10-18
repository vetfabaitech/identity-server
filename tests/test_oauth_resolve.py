"""Which account an OAuth sign-in becomes (spec SI-5): link, then verified email, then a new pending account."""

from collections.abc import Callable
from pathlib import Path

import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from identity import store
from identity.config import Settings
from identity.oauth import OAuthError, Profile
from identity.oauth.resolve import resolve_user
from identity.store import User
from tests.conftest import make_settings

pytestmark = pytest.mark.db


def profile(email: str | None, *, verified: bool = True, pid: str | None = None, provider: str = "github") -> Profile:
    return Profile(
        provider=provider,  # pyright: ignore[reportArgumentType]
        provider_user_id=pid or (email or "anon").split("@")[0] + "-id",
        email=email,
        email_verified=verified,
        display_name="Octo",
    )


@pytest.fixture
def admin_settings(login_url: str, keys_dir: Path) -> Settings:
    return make_settings(login_url, keys_dir, admin_emails="boss@dev.vetfab.local")


def audit_actions(owner_url: str, user_id: object) -> list[str]:
    with psycopg.connect(owner_url) as conn:
        rows = conn.execute("SELECT action FROM identity.audit WHERE user_id = %s ORDER BY id", (user_id,)).fetchall()
    return [r[0] for r in rows]


async def test_creates_pending_user(pool: AsyncConnectionPool, settings: Settings, owner_url: str) -> None:
    async with pool.connection() as conn:
        resolved = await resolve_user(conn, profile("new-octo@dev.vetfab.local"), settings)
    assert resolved.outcome == "created"
    assert (resolved.user.email, resolved.user.status, resolved.user.role) == (
        "new-octo@dev.vetfab.local",
        "pending",
        "beta_user",
    )
    assert resolved.user.display_name == "Octo"
    assert audit_actions(owner_url, resolved.user.id) == ["user_created", "oauth_linked"]


async def test_matched_by_provider_id(pool: AsyncConnectionPool, settings: Settings) -> None:
    async with pool.connection() as conn:
        first = await resolve_user(conn, profile("match@dev.vetfab.local", pid="m-1"), settings)
        # Same provider id, changed (even unverified) email: still the same account.
        again = await resolve_user(conn, profile("renamed@dev.vetfab.local", verified=False, pid="m-1"), settings)
    assert again.outcome == "matched"
    assert again.user.id == first.user.id


async def test_links_by_verified_email(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User]
) -> None:
    existing = make_user("Linked@Dev.Vetfab.Local", status="approved")
    async with pool.connection() as conn:
        resolved = await resolve_user(conn, profile("linked@dev.vetfab.local"), settings)
        found = await store.find_user_by_oauth(conn, "github", "linked-id")
    assert resolved.outcome == "linked"
    assert resolved.user.id == existing.id and resolved.user.status == "approved"
    assert found is not None and found.id == existing.id


async def test_the_same_person_can_link_both_providers(pool: AsyncConnectionPool, settings: Settings) -> None:
    async with pool.connection() as conn:
        gh = await resolve_user(conn, profile("both@dev.vetfab.local", pid="gh-9"), settings)
        g = await resolve_user(conn, profile("both@dev.vetfab.local", pid="g-9", provider="google"), settings)
    assert (gh.outcome, g.outcome) == ("created", "linked")
    assert gh.user.id == g.user.id


async def test_unverified_email_never_links(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User]
) -> None:
    existing = make_user("victim@dev.vetfab.local")
    async with pool.connection() as conn:
        with pytest.raises(OAuthError) as caught:
            await resolve_user(conn, profile("victim@dev.vetfab.local", verified=False), settings)
        link = await store.find_user_by_oauth(conn, "github", "victim-id")
        still = await store.find_user_by_email(conn, "victim@dev.vetfab.local")
    assert caught.value.reason == "no_verified_email"
    assert link is None
    assert still is not None and still.id == existing.id


async def test_unverified_email_never_creates_an_account(pool: AsyncConnectionPool, settings: Settings) -> None:
    async with pool.connection() as conn:
        with pytest.raises(OAuthError):
            await resolve_user(conn, profile("unclaimed@dev.vetfab.local", verified=False), settings)
        assert await store.find_user_by_email(conn, "unclaimed@dev.vetfab.local") is None


async def test_no_email_raises(pool: AsyncConnectionPool, settings: Settings) -> None:
    async with pool.connection() as conn:
        with pytest.raises(OAuthError) as caught:
            await resolve_user(conn, profile(None, pid="no-email"), settings)
    assert caught.value.reason == "no_verified_email"


async def test_admin_email_is_created_approved_admin(
    pool: AsyncConnectionPool, admin_settings: Settings, owner_url: str
) -> None:
    async with pool.connection() as conn:
        resolved = await resolve_user(conn, profile("Boss@Dev.Vetfab.Local", pid="boss-1"), admin_settings)
    assert (resolved.user.role, resolved.user.status) == ("admin", "approved")
    assert "admin_bootstrapped" in audit_actions(owner_url, resolved.user.id)


async def test_an_existing_admin_email_account_is_promoted_on_sign_in(
    pool: AsyncConnectionPool, admin_settings: Settings, make_user: Callable[..., User]
) -> None:
    make_user("boss@dev.vetfab.local", status="pending")
    async with pool.connection() as conn:
        resolved = await resolve_user(conn, profile("boss@dev.vetfab.local", pid="boss-2"), admin_settings)
    assert (resolved.outcome, resolved.user.role, resolved.user.status) == ("linked", "admin", "approved")


async def test_duplicate_email_insert_recovers(
    pool: AsyncConnectionPool, settings: Settings, make_user: Callable[..., User], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A concurrent first sign-in created the row between our lookup and our insert."""
    existing = make_user("race@dev.vetfab.local")
    real = store.find_user_by_email
    calls = {"n": 0}

    async def first_lookup_misses(conn: object, email: str) -> User | None:
        calls["n"] += 1
        return None if calls["n"] == 1 else await real(conn, email)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(store, "find_user_by_email", first_lookup_misses)
    async with pool.connection() as conn:
        resolved = await resolve_user(conn, profile("race@dev.vetfab.local"), settings)
    assert resolved.outcome == "linked"
    assert resolved.user.id == existing.id
