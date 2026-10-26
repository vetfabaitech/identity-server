"""Queries over `public.users` and the `identity` schema. Every function takes a connection inside the caller's
transaction (the pool's connection context commits on success)."""

from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb

Status = Literal["pending", "approved", "rejected", "suspended"]
STATUSES: tuple[Status, ...] = ("pending", "approved", "rejected", "suspended")
# Statuses that may hold a session. Pending accounts sign in and the LMS shows its waiting page.
ACTIVE_STATUSES = frozenset({"approved", "pending"})

AuditAction = Literal[
    "signin",
    "signin_failed",
    "refresh",
    "logout",
    "revoke",
    "reuse_detected",
    "test_signin",
    "status_change",
    "password_set",
    "user_created",
    "oauth_signin",
    "oauth_linked",
    "admin_bootstrapped",
]
Provider = Literal["github", "google"]

_USER_COLUMNS = "id, email, display_name, status, password_hash, role"
MAX_USER_AGENT = 512
MAX_IP = 64


@dataclass(frozen=True, slots=True)
class User:
    id: UUID
    email: str
    display_name: str
    status: str
    password_hash: str | None
    role: str = "beta_user"

    @property
    def active(self) -> bool:
        return self.status in ACTIVE_STATUSES


def _user(row: Any) -> User:
    return User(id=row[0], email=row[1], display_name=row[2], status=row[3], password_hash=row[4], role=row[5])


def normalise_email(email: str) -> str:
    return email.strip().lower()


async def find_user_by_email(conn: AsyncConnection[Any], email: str) -> User | None:
    cur = await conn.execute(
        f"SELECT {_USER_COLUMNS} FROM public.users WHERE lower(email) = %s",  # noqa: S608  # constant column list
        (normalise_email(email),),
    )
    row = await cur.fetchone()
    return _user(row) if row else None


async def get_user(conn: AsyncConnection[Any], user_id: UUID) -> User | None:
    cur = await conn.execute(f"SELECT {_USER_COLUMNS} FROM public.users WHERE id = %s", (user_id,))  # noqa: S608
    row = await cur.fetchone()
    return _user(row) if row else None


async def list_users_by_emails(conn: AsyncConnection[Any], emails: list[str]) -> list[User]:
    wanted = [normalise_email(e) for e in emails]
    cur = await conn.execute(
        f"""SELECT {_USER_COLUMNS} FROM public.users WHERE lower(email) = ANY(%s)
             ORDER BY array_position(%s::text[], lower(email))""",  # noqa: S608  # constant column list
        (wanted, wanted),
    )
    return [_user(row) for row in await cur.fetchall()]


async def create_user(
    conn: AsyncConnection[Any], email: str, display_name: str, status: Status, role: str = "beta_user"
) -> User:
    cur = await conn.execute(
        f"""INSERT INTO public.users (email, display_name, status, role) VALUES (%s, %s, %s, %s)
            RETURNING {_USER_COLUMNS}""",  # noqa: S608  # constant column list
        (normalise_email(email), display_name.strip(), status, role),
    )
    row = await cur.fetchone()
    assert row is not None
    return _user(row)


async def set_password(conn: AsyncConnection[Any], user_id: UUID, password_hash: str) -> None:
    await conn.execute("UPDATE public.users SET password_hash = %s WHERE id = %s", (password_hash, user_id))


async def set_status(conn: AsyncConnection[Any], user_id: UUID, status: Status) -> None:
    await conn.execute("UPDATE public.users SET status = %s WHERE id = %s", (status, user_id))


async def promote_admin(conn: AsyncConnection[Any], user_id: UUID) -> None:
    """The IDENTITY_ADMIN_EMAILS bootstrap (spec SI-5): an approved administrator."""
    await conn.execute("UPDATE public.users SET role = 'admin', status = 'approved' WHERE id = %s", (user_id,))


async def find_user_by_oauth(conn: AsyncConnection[Any], provider: Provider, provider_user_id: str) -> User | None:
    cur = await conn.execute(
        f"""SELECT {", ".join(f"u.{c}" for c in _USER_COLUMNS.split(", "))}
              FROM identity.oauth_accounts a JOIN public.users u ON u.id = a.user_id
             WHERE a.provider = %s AND a.provider_user_id = %s""",  # noqa: S608  # constant column list
        (provider, provider_user_id),
    )
    row = await cur.fetchone()
    return _user(row) if row else None


async def link_oauth(
    conn: AsyncConnection[Any], user_id: UUID, provider: Provider, provider_user_id: str, email: str | None
) -> None:
    await conn.execute(
        """INSERT INTO identity.oauth_accounts (provider, provider_user_id, user_id, email_at_link)
           VALUES (%s, %s, %s, %s)""",
        (provider, provider_user_id, user_id, email[:320] if email else None),
    )


async def touch_login(conn: AsyncConnection[Any], user_id: UUID) -> None:
    await conn.execute("UPDATE public.users SET last_login_at = now() WHERE id = %s", (user_id,))


async def audit(
    conn: AsyncConnection[Any],
    action: AuditAction,
    *,
    user_id: UUID | None = None,
    actor_id: UUID | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    await conn.execute(
        """INSERT INTO identity.audit (action, user_id, actor_id, ip, user_agent, metadata)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (
            action,
            user_id,
            actor_id,
            ip[:MAX_IP] if ip else None,
            user_agent[:MAX_USER_AGENT] if user_agent else None,
            Jsonb(metadata or {}),
        ),
    )


# --------------------------------------------------------------------------- rate limit (fixed window per key)


async def rate_limited(conn: AsyncConnection[Any], limits: dict[str, int], *, window_seconds: int) -> bool:
    """Whether any counter in `limits` (key -> allowed failures) has reached its limit inside the window."""
    cur = await conn.execute(
        """SELECT 1 FROM identity.signin_attempts a
            JOIN unnest(%s::text[], %s::int[]) AS l(key, allowed) ON l.key = a.key
            WHERE a.count >= l.allowed AND a.window_start > now() - make_interval(secs => %s)
            LIMIT 1""",
        (list(limits), list(limits.values()), window_seconds),
    )
    return await cur.fetchone() is not None


async def record_failure(conn: AsyncConnection[Any], keys: list[str], *, window_seconds: int) -> None:
    for key in keys:
        await conn.execute(
            """INSERT INTO identity.signin_attempts AS a (key, window_start, count) VALUES (%s, now(), 1)
               ON CONFLICT (key) DO UPDATE SET
                 count = CASE WHEN a.window_start <= now() - make_interval(secs => %s) THEN 1 ELSE a.count + 1 END,
                 window_start = CASE WHEN a.window_start <= now() - make_interval(secs => %s)
                                     THEN now() ELSE a.window_start END""",
            (key[:400], window_seconds, window_seconds),
        )


async def clear_failures(conn: AsyncConnection[Any], keys: list[str]) -> None:
    await conn.execute("DELETE FROM identity.signin_attempts WHERE key = ANY(%s)", (keys,))
