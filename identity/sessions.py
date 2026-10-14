"""Refresh sessions (spec TD-6).

A refresh token is 32 random bytes (base64url), sent only in the identity service's own cookie and stored only as its
SHA-256. Every use rotates it: the presented token is marked rotated and a new one in the same family is issued.

* A token rotated less than `refresh_grace_seconds` ago still yields an access token, but no new refresh token: two
  tabs renewing at once with the same cookie both stay signed in, and the cookie the first one set stays current.
* An older rotated token, or any token of a revoked family, is reuse: the whole family is revoked, which signs out
  whoever holds the current token (it may have been stolen).
* An account that is no longer approved or pending loses the session.
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

from psycopg import AsyncConnection

from identity import store
from identity.config import Settings
from identity.store import User

RevokeReason = Literal["logout", "reuse", "inactive", "admin", "password"]
TOKEN_BYTES = 32
_MIN_TOKEN_LENGTH, _MAX_TOKEN_LENGTH = 40, 64


@dataclass(frozen=True, slots=True)
class Issued:
    user: User
    # None inside the grace window: keep the cookie that is already there.
    refresh_token: str | None


@dataclass(frozen=True, slots=True)
class Rejected:
    reason: Literal["unknown", "expired", "revoked", "reuse", "inactive"]


Renewal = Issued | Rejected


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_hash(raw: str) -> bytes:
    return hashlib.sha256(raw.encode("ascii", "replace")).digest()


async def issue(
    conn: AsyncConnection[Any], user: User, settings: Settings, user_agent: str | None, *, family_id: UUID | None = None
) -> str:
    raw = new_token()
    await conn.execute(
        """INSERT INTO identity.refresh_tokens (family_id, user_id, token_hash, expires_at, user_agent)
           VALUES (%s, %s, %s, now() + make_interval(days => %s), %s)""",
        (
            family_id or uuid.uuid4(),
            user.id,
            token_hash(raw),
            settings.refresh_token_days,
            user_agent[: store.MAX_USER_AGENT] if user_agent else None,
        ),
    )
    return raw


async def _revoke_family(conn: AsyncConnection[Any], family_id: UUID, reason: RevokeReason) -> None:
    await conn.execute(
        """UPDATE identity.refresh_tokens SET revoked_at = now(), revoked_reason = %s
            WHERE family_id = %s AND revoked_at IS NULL""",
        (reason, family_id),
    )


async def renew(conn: AsyncConnection[Any], raw: str | None, settings: Settings, user_agent: str | None) -> Renewal:
    if not raw or not _MIN_TOKEN_LENGTH <= len(raw) <= _MAX_TOKEN_LENGTH:
        return Rejected("unknown")
    cur = await conn.execute(
        """SELECT id, family_id, user_id, revoked_at IS NOT NULL, rotated_at IS NOT NULL,
                  rotated_at > now() - make_interval(secs => %s), expires_at <= now()
             FROM identity.refresh_tokens WHERE token_hash = %s FOR UPDATE""",
        (settings.refresh_grace_seconds, token_hash(raw)),
    )
    row = await cur.fetchone()
    if row is None:
        return Rejected("unknown")
    token_id, family_id, user_id, revoked, rotated, in_grace, expired = row
    if revoked:
        return Rejected("revoked")
    if rotated and not in_grace:
        await _revoke_family(conn, family_id, "reuse")
        await store.audit(conn, "reuse_detected", user_id=user_id, metadata={"family_id": str(family_id)})
        return Rejected("reuse")
    if expired:
        return Rejected("expired")
    user = await store.get_user(conn, user_id)
    if user is None or not user.active:
        await _revoke_family(conn, family_id, "inactive")
        return Rejected("inactive")
    if rotated:  # inside the grace window
        return Issued(user=user, refresh_token=None)
    await conn.execute(
        "UPDATE identity.refresh_tokens SET rotated_at = now(), last_used_at = now() WHERE id = %s", (token_id,)
    )
    return Issued(user=user, refresh_token=await issue(conn, user, settings, user_agent, family_id=family_id))


async def revoke(conn: AsyncConnection[Any], raw: str | None, reason: RevokeReason) -> UUID | None:
    """Revokes the session the token belongs to; returns its user id, or None for an unknown token."""
    if not raw or not _MIN_TOKEN_LENGTH <= len(raw) <= _MAX_TOKEN_LENGTH:
        return None
    cur = await conn.execute(
        "SELECT family_id, user_id FROM identity.refresh_tokens WHERE token_hash = %s", (token_hash(raw),)
    )
    row = await cur.fetchone()
    if row is None:
        return None
    await _revoke_family(conn, row[0], reason)
    return row[1]


async def revoke_user(conn: AsyncConnection[Any], user_id: UUID, reason: RevokeReason) -> int:
    cur = await conn.execute(
        """UPDATE identity.refresh_tokens SET revoked_at = now(), revoked_reason = %s
            WHERE user_id = %s AND revoked_at IS NULL""",
        (reason, user_id),
    )
    return cur.rowcount
