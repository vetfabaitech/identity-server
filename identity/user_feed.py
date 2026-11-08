"""The user feed (CONTRACT.md, "User feed"): the few user fields products keep their own copy of, as signed documents.

Change capture is the database's (migration 0006): a trigger on `public.users` appends to `identity.user_events` and
bumps `identity.user_versions` whoever writes, this service or the IDE. This module only reads those tables, asks the
purge function to drop old events, and signs what it read.

* A snapshot is `{"id", "version", "deleted": false, "email", "display_name", "status"}` for a live user, and
  `{"id", "version", "deleted": true}` (no personal data) for a deleted or unknown one. `version` is per user and only
  grows, so a consumer keeps whichever copy has the higher version and duplicates or reordering do no harm.
* Reads that combine the head with a page run in one REPEATABLE READ snapshot, so `head` describes exactly the page
  it came with: every change up to `head` is in the page, every later one has a higher seq.
* A document is a compact JWS signed RS256 with the access-token key (published in the JWKS) under `typ:
  user-feed+jwt`, so it can never pass for an access token, nor an access token for a document.
* A page document echoes the request it answers (`after` and the effective `limit`), so a still-valid document cannot
  be replayed as the answer to a different request; a `user` document names its id inside `user`.
"""

import time
import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

import jwt
from psycopg import AsyncConnection

from identity.config import Settings
from identity.keys import KeyRing

# The pg_advisory_xact_lock key the trigger takes before it allocates a seq (migration 0006): ASCII "IDUSEREV".
USER_EVENTS_LOCK = 0x4944555345524556
DOCUMENT_TYPE = "user-feed+jwt"
DOCUMENT_SECONDS = 300
DEFAULT_EVENTS, MAX_EVENTS = 200, 500
DEFAULT_USERS, MAX_USERS = 500, 1000
MAX_SEQ = 2**63 - 1

Kind = Literal["user-events", "user", "users"]

_SNAPSHOT = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
_BOUNDS = "SELECT coalesce(max(seq), 0), min(seq) FROM identity.user_events"
_EVENTS = """SELECT seq, type, occurred_at, user_id, version, email, display_name, status
               FROM identity.user_events WHERE seq > %s ORDER BY seq LIMIT %s"""
_USER = """SELECT u.id IS NOT NULL, coalesce(v.version, CASE WHEN u.id IS NULL THEN 0 ELSE 1 END),
                  u.email, u.display_name, u.status
             FROM (VALUES (%s::uuid)) AS k (id)
             LEFT JOIN public.users u ON u.id = k.id
             LEFT JOIN identity.user_versions v ON v.user_id = k.id"""
# A user with no version row was written while the triggers were off; it counts as version 1 (migration 0006).
_PAGE = """SELECT u.id, coalesce(v.version, 1), u.email, u.display_name, u.status
             FROM public.users u LEFT JOIN identity.user_versions v ON v.user_id = u.id"""
_FIRST_PAGE = _PAGE + " ORDER BY u.id LIMIT %s"
_NEXT_PAGE = _PAGE + " WHERE u.id > %s ORDER BY u.id LIMIT %s"


def live(user_id: UUID, version: int, email: str, display_name: str, status: str) -> dict[str, Any]:
    return {
        "id": str(user_id),
        "version": version,
        "deleted": False,
        "email": email,
        "display_name": display_name,
        "status": status,
    }


def deleted(user_id: UUID, version: int) -> dict[str, Any]:
    return {"id": str(user_id), "version": version, "deleted": True}


def rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


async def read_events(conn: AsyncConnection[Any], after: int, limit: int) -> dict[str, Any]:
    """Events with seq > `after`, ascending, and the bounds of what is retained (one snapshot).

    Starts its own transaction: call it on a connection with none in progress."""
    async with conn.transaction():
        await conn.execute(_SNAPSHOT)
        bounds = await (await conn.execute(_BOUNDS)).fetchone()
        rows = await (await conn.execute(_EVENTS, (after, limit))).fetchall()
    assert bounds is not None
    head, oldest = bounds
    events = [
        {
            "seq": seq,
            "type": kind,
            "occurred_at": rfc3339(occurred_at),
            "user": deleted(user_id, version)
            if kind == "user.deleted"
            else live(user_id, version, email, display_name, status),
        }
        for seq, kind, occurred_at, user_id, version, email, display_name, status in rows
    ]
    return {
        "after": after,
        "limit": limit,
        "events": events,
        "next": events[-1]["seq"] if events else after,
        "head": head,
        "oldest": head + 1 if oldest is None else oldest,
    }


async def read_user(conn: AsyncConnection[Any], user_id: UUID) -> dict[str, Any]:
    """The current snapshot of one user. Unknown: deleted at version 0. Deleted: deleted at its last version."""
    row = await (await conn.execute(_USER, (user_id,))).fetchone()
    assert row is not None
    exists, version, email, display_name, status = row
    return live(user_id, version, email, display_name, status) if exists else deleted(user_id, version)


async def read_users(conn: AsyncConnection[Any], after: UUID | None, limit: int) -> dict[str, Any]:
    """Live users with id > `after`, by id, and the event head read first (one snapshot).

    Starts its own transaction: call it on a connection with none in progress."""
    async with conn.transaction():
        await conn.execute(_SNAPSHOT)
        bounds = await (await conn.execute(_BOUNDS)).fetchone()
        if after is None:
            cur = await conn.execute(_FIRST_PAGE, (limit + 1,))
        else:
            cur = await conn.execute(_NEXT_PAGE, (after, limit + 1))
        rows = await cur.fetchall()
    assert bounds is not None
    page = [live(*row) for row in rows[:limit]]
    return {
        "after": None if after is None else str(after),
        "limit": limit,
        "users": page,
        "next": page[-1]["id"] if len(rows) > limit else None,
        "head": bounds[0],
    }


async def purge(conn: AsyncConnection[Any], retention_days: int, max_rows: int) -> int:
    """Deletes up to about `max_rows` of the oldest events older than the retention, through the definer function
    (a prefix by seq, never the newest event, never less than 7 days). Returns how many went."""
    row = await (await conn.execute("SELECT identity.purge_user_events(%s, %s)", (retention_days, max_rows))).fetchone()
    assert row is not None
    return int(row[0])


def sign(
    keys: KeyRing, settings: Settings, audience: str, kind: Kind, body: dict[str, Any], now: int | None = None
) -> str:
    """A feed document for one service: the access-token key and issuer, `aud` the service, valid 300 seconds."""
    issued_at = int(time.time()) if now is None else now
    claims = {
        "iss": settings.issuer,
        "aud": audience,
        "iat": issued_at,
        "exp": issued_at + DOCUMENT_SECONDS,
        "jti": uuid.uuid4().hex,
        "kind": kind,
        **body,
    }
    return jwt.encode(
        claims, keys.signing_key, algorithm="RS256", headers={"kid": keys.signing_kid, "typ": DOCUMENT_TYPE}
    )
