"""Which account an OAuth sign-in becomes (spec SI-5).

1. A known link (provider, provider user id): that account, whatever email the provider reports now.
2. Otherwise only a provider-verified email is trusted: an account with that email is linked; with none, a new
   `pending` account is created and linked. An unverified or missing email neither links nor creates (an attacker
   could otherwise pre-claim someone else's address and receive their later verified sign-in).
3. An active (pending or approved) account whose email is in IDENTITY_ADMIN_EMAILS becomes an approved
   administrator (the IDE's bootstrap). A suspended or rejected one stays as it is.

A first sign-in racing another for the same email or provider id recovers by re-reading instead of failing.
"""

from dataclasses import dataclass
from typing import Any, Literal

from psycopg import AsyncConnection
from psycopg.errors import UniqueViolation

from identity import store
from identity.config import Settings
from identity.oauth.base import OAuthError, Profile
from identity.store import User


@dataclass(frozen=True, slots=True)
class Resolved:
    user: User
    outcome: Literal["matched", "linked", "created"]


async def _link_or_create(conn: AsyncConnection[Any], profile: Profile, email: str) -> Resolved:
    existing = await store.find_user_by_email(conn, email)
    if existing is not None:
        user, outcome = existing, "linked"
    else:
        user, outcome = (
            await store.create_user(conn, email, profile.display_name or email.split("@")[0], "pending"),
            "created",
        )
        await store.audit(conn, "user_created", user_id=user.id, metadata={"provider": profile.provider})
    await store.link_oauth(conn, user.id, profile.provider, profile.provider_user_id, email)
    await store.audit(conn, "oauth_linked", user_id=user.id, metadata={"provider": profile.provider})
    return Resolved(user, outcome)


async def _resolve(conn: AsyncConnection[Any], profile: Profile) -> Resolved:
    matched = await store.find_user_by_oauth(conn, profile.provider, profile.provider_user_id)
    if matched is not None:
        return Resolved(matched, "matched")
    if not (profile.email and profile.email_verified):
        raise OAuthError("no_verified_email")
    try:
        async with conn.transaction():  # a savepoint: a lost race rolls back only this attempt
            return await _link_or_create(conn, profile, profile.email)
    except UniqueViolation:
        matched = await store.find_user_by_oauth(conn, profile.provider, profile.provider_user_id)
        if matched is not None:
            return Resolved(matched, "matched")
        return await _link_or_create(conn, profile, profile.email)


async def resolve_user(conn: AsyncConnection[Any], profile: Profile, settings: Settings) -> Resolved:
    resolved = await _resolve(conn, profile)
    user = resolved.user
    # Only an active account is promoted: an operator's suspension or rejection is never undone by signing in.
    if (
        user.active
        and store.normalise_email(user.email) in settings.admin_email_list
        and (user.role, user.status) != ("admin", "approved")
    ):
        await store.promote_admin(conn, user.id)
        await store.audit(conn, "admin_bootstrapped", user_id=user.id, metadata={"previous": [user.role, user.status]})
        refreshed = await store.get_user(conn, user.id)
        assert refreshed is not None
        resolved = Resolved(refreshed, resolved.outcome)
    return resolved
