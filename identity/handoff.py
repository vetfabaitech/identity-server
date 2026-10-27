"""SSO hand-off tickets (docs/sso-handoff.md).

A ticket is 32 random bytes (base64url), stored only as its SHA-256. It is bound at issue to the signed-in user, the
central session (refresh-token family) it came from, the source service, the one destination service and a return
path, and it works once, for `IDENTITY_HANDOFF_TICKET_SECONDS`. Redemption is one atomic UPDATE: of any number of
concurrent attempts exactly one gets the row back. A ticket presented by the wrong service, or after it expired, is
consumed too, so a stolen one cannot be retried by its rightful holder or anyone else.

Unlike the access token (reusable for 15 minutes, audience shared by every product, in a URL fragment), a ticket is
useless to anyone who is not the destination's backend, and useless to it a second time.
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

from psycopg import AsyncConnection

from identity import store

TICKET_BYTES = 32
_MIN_LENGTH, _MAX_LENGTH = 40, 64
# Unredeemed tickets one session may hold at once: a runaway page cannot fill the table.
MAX_OUTSTANDING = 20


def ticket_hash(raw: str) -> bytes:
    return hashlib.sha256(raw.encode("ascii", "replace")).digest()


async def issue(
    conn: AsyncConnection[Any],
    *,
    family_id: UUID,
    user_id: UUID,
    source: str,
    target: str,
    return_path: str,
    seconds: int,
) -> str | None:
    """A new ticket, or None when this session already holds too many unredeemed ones."""
    await conn.execute("DELETE FROM identity.handoff_tickets WHERE expires_at < now() - interval '1 hour'")
    cur = await conn.execute(
        """SELECT count(*) FROM identity.handoff_tickets
            WHERE family_id = %s AND consumed_at IS NULL AND expires_at > now()""",
        (family_id,),
    )
    row = await cur.fetchone()
    if row is not None and row[0] >= MAX_OUTSTANDING:
        return None
    raw = secrets.token_urlsafe(TICKET_BYTES)
    await conn.execute(
        """INSERT INTO identity.handoff_tickets
             (ticket_hash, family_id, user_id, source_service, target_service, return_path, expires_at)
           VALUES (%s, %s, %s, %s, %s, %s, now() + make_interval(secs => %s))""",
        (ticket_hash(raw), family_id, user_id, source, target, return_path, seconds),
    )
    return raw


@dataclass(frozen=True, slots=True)
class Redeemed:
    user_id: UUID
    source_service: str
    return_path: str


@dataclass(frozen=True, slots=True)
class Refused:
    # `unknown`: never issued (or purged). `reused`: already redeemed. `expired`, `wrong_service`: consumed by this
    # attempt. `session_ended`: the central session was revoked or expired. `inactive`: the account is suspended.
    # `source_disabled` is set by the route: the source service was disabled after the ticket was issued.
    reason: Literal["unknown", "reused", "expired", "wrong_service", "session_ended", "inactive", "source_disabled"]


async def redeem(conn: AsyncConnection[Any], raw: str | None, service_id: str) -> Redeemed | Refused:
    if not raw or not _MIN_LENGTH <= len(raw) <= _MAX_LENGTH:
        return Refused("unknown")
    digest = ticket_hash(raw)
    cur = await conn.execute(
        """UPDATE identity.handoff_tickets SET consumed_at = now()
            WHERE ticket_hash = %s AND consumed_at IS NULL
        RETURNING family_id, user_id, source_service, target_service, return_path, expires_at <= now()""",
        (digest,),
    )
    row = await cur.fetchone()
    if row is None:
        cur = await conn.execute("SELECT 1 FROM identity.handoff_tickets WHERE ticket_hash = %s", (digest,))
        return Refused("reused" if await cur.fetchone() else "unknown")
    family_id, user_id, source, target, return_path, expired = row
    if target != service_id:
        return Refused("wrong_service")
    if expired:
        return Refused("expired")
    cur = await conn.execute(
        """SELECT EXISTS (SELECT 1 FROM identity.refresh_tokens
                           WHERE family_id = %s AND revoked_at IS NULL AND expires_at > now())""",
        (family_id,),
    )
    alive = await cur.fetchone()
    if alive is None or not alive[0]:
        return Refused("session_ended")
    user = await store.get_user(conn, user_id)
    if user is None or not user.active:
        return Refused("inactive")
    return Redeemed(user_id=user_id, source_service=source, return_path=return_path)
