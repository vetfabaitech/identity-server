"""Database access: one async psycopg pool whose every connection runs as `identity_app`.

The login (IDENTITY_DATABASE_URL) is NOINHERIT and a member of `identity_app` only, so it has no privileges until
`SET ROLE identity_app`, which the pool applies to each new connection. `login_problems()` lets the app refuse a
privileged login (superuser, BYPASSRLS) outside development, as the LMS API does (ADR-0001).
"""

from typing import Any

from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

RUNTIME_ROLE = "identity_app"


async def _configure(conn: AsyncConnection[Any]) -> None:
    await conn.execute(f"SET ROLE {RUNTIME_ROLE}")
    await conn.commit()


async def open_pool(url: str, *, min_size: int = 1, max_size: int = 10) -> AsyncConnectionPool[Any]:
    pool: AsyncConnectionPool[Any] = AsyncConnectionPool(
        url, min_size=min_size, max_size=max_size, open=False, configure=_configure
    )
    await pool.open(wait=True, timeout=15)
    return pool


async def login_problems(conn: AsyncConnection[Any]) -> list[str]:
    """Why the database login is unsafe for serving requests (empty when it is safe)."""
    row = await (
        await conn.execute(
            """SELECT r.rolsuper, r.rolbypassrls, pg_has_role(session_user, %s, 'MEMBER')
                 FROM pg_roles r WHERE r.rolname = session_user""",
            (RUNTIME_ROLE,),
        )
    ).fetchone()
    if row is None:
        return ["login role not found"]
    superuser, bypass, member = row
    problems = []
    if superuser:
        problems.append("login role is a superuser")
    if bypass:
        problems.append("login role has BYPASSRLS")
    if not member:
        problems.append(f"login role is not a member of {RUNTIME_ROLE}")
    return problems
