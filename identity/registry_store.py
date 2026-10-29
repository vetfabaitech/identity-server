# ruff: noqa: S608  # every f-string interpolates only the constant _COLUMNS list; all values are bound parameters
"""The managed service registry in PostgreSQL (`identity.services`, migration 0005).

Every change is one SQL statement (atomic), so identity-service instances sharing the database never see a half-made
change. There is no DELETE: a service is disabled, and its row, owner and audit trail stay. Plaintext secrets never
reach this module; it receives and stores SHA-256 hashes only.
"""

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from psycopg import AsyncConnection, errors, sql

from identity.services import Registry, Service

log = logging.getLogger("identity")

_COLUMNS = (
    "id, display_name, description, owner_team, owner_user_id, environment, base_url, callback_path, roles, "
    "return_path_prefixes, session_seconds, status, source, secret_sha256, previous_secret_sha256, "
    "previous_secret_expires_at, created_at, updated_at"
)
# Fields a caller may change through `update`. Everything else (status, secrets, owner) has its own operation.
EDITABLE = frozenset(
    {
        "display_name",
        "description",
        "owner_team",
        "environment",
        "base_url",
        "callback_path",
        "roles",
        "return_path_prefixes",
        "session_seconds",
    }
)


class Conflict(Exception):
    """The id or the base URL is already registered."""

    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


def _service(row: Any) -> Service:
    (sid, name, desc, team, owner, env, base, callback, roles, prefixes, seconds, status, source, secret) = row[:14]
    previous, previous_expires, created, updated = row[14:18]
    return Service(
        id=sid,
        display_name=name,
        base_url=base,
        environment=env,
        enabled=status == "active",
        callback_path=callback,
        roles=tuple(roles),
        secret_sha256=secret,
        status=status,
        description=desc,
        owner_team=team,
        owner_user_id=owner,
        return_path_prefixes=tuple(prefixes),
        session_seconds=seconds,
        source=source,
        previous_secret_sha256=previous,
        previous_secret_expires_at=previous_expires.timestamp() if previous_expires else None,
        created_at=created,
        updated_at=updated,
    )


async def list_all(conn: AsyncConnection[Any]) -> list[Service]:
    cur = await conn.execute(f"SELECT {_COLUMNS} FROM identity.services ORDER BY created_at, id")  # noqa: S608  # constant column list
    return [_service(row) for row in await cur.fetchall()]


async def load_registry(conn: AsyncConnection[Any]) -> Registry:
    """Every service, with its current status. `Registry`'s lookups only ever return the active ones."""
    return Registry(tuple(await list_all(conn)))


async def get(conn: AsyncConnection[Any], service_id: str) -> Service | None:
    cur = await conn.execute(f"SELECT {_COLUMNS} FROM identity.services WHERE id = %s", (service_id,))  # noqa: S608
    row = await cur.fetchone()
    return _service(row) if row else None


async def owner_emails(conn: AsyncConnection[Any], user_ids: set[UUID]) -> dict[UUID, str]:
    if not user_ids:
        return {}
    cur = await conn.execute("SELECT id, email FROM public.users WHERE id = ANY(%s)", (list(user_ids),))
    return {row[0]: row[1] for row in await cur.fetchall()}


def _conflict(exc: errors.UniqueViolation) -> Conflict:
    constraint = exc.diag.constraint_name or ""
    return Conflict("base_url" if "base_url" in constraint else "id")


async def insert(
    conn: AsyncConnection[Any],
    fields: dict[str, Any],
    *,
    secret_sha256: str,
    status: str,
    source: str,
    owner_user_id: UUID | None,
    created_by: UUID | None,
) -> Service:
    """Registers a service. Raises `Conflict` for a duplicate id or base URL (decided by the database, not a race)."""
    try:
        cur = await conn.execute(
            f"""INSERT INTO identity.services
                  (id, display_name, description, owner_team, owner_user_id, environment, base_url, callback_path,
                   roles, return_path_prefixes, session_seconds, status, source, secret_sha256, created_by,
                   created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        clock_timestamp(), clock_timestamp())
                RETURNING {_COLUMNS}""",
            (
                fields["id"],
                fields["display_name"],
                fields["description"],
                fields["owner_team"],
                owner_user_id,
                fields["environment"],
                fields["base_url"],
                fields["callback_path"],
                list(fields["roles"]),
                list(fields["return_path_prefixes"]),
                fields["session_seconds"],
                status,
                source,
                secret_sha256,
                created_by,
            ),
        )
    except errors.UniqueViolation as exc:
        raise _conflict(exc) from exc
    row = await cur.fetchone()
    assert row is not None
    return _service(row)


async def update(conn: AsyncConnection[Any], service_id: str, changes: dict[str, Any]) -> Service | None:
    """Applies already-validated changes to the editable columns in one statement."""
    columns = [c for c in changes if c in EDITABLE]
    if not columns:
        return await get(conn, service_id)
    assignments = sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(c)) for c in columns)
    values = [list(changes[c]) if isinstance(changes[c], tuple) else changes[c] for c in columns]
    query = sql.SQL("UPDATE identity.services SET {}, updated_at = now() WHERE id = %s RETURNING {}").format(
        assignments, sql.SQL(_COLUMNS)
    )
    try:
        cur = await conn.execute(query, (*values, service_id))
    except errors.UniqueViolation as exc:
        raise _conflict(exc) from exc
    row = await cur.fetchone()
    return _service(row) if row else None


async def set_status(conn: AsyncConnection[Any], service_id: str, status: str, actor: UUID) -> Service | None:
    approving = status == "active"
    cur = await conn.execute(
        f"""UPDATE identity.services
               SET status = %s, updated_at = now(),
                   approved_by = CASE WHEN %s THEN %s ELSE approved_by END,
                   approved_at = CASE WHEN %s THEN now() ELSE approved_at END
             WHERE id = %s RETURNING {_COLUMNS}""",
        (status, approving, actor, approving, service_id),
    )
    row = await cur.fetchone()
    return _service(row) if row else None


async def rotate_secret(
    conn: AsyncConnection[Any], service_id: str, new_hash: str, grace_seconds: int
) -> Service | None:
    """Makes `new_hash` current. The old one keeps working for `grace_seconds` (0: revoked at once), in one statement."""
    cur = await conn.execute(
        f"""UPDATE identity.services
               SET previous_secret_sha256 = CASE WHEN %s > 0 THEN secret_sha256 END,
                   previous_secret_expires_at = CASE WHEN %s > 0 THEN now() + make_interval(secs => %s) END,
                   secret_sha256 = %s, secret_rotated_at = now(), updated_at = now()
             WHERE id = %s RETURNING {_COLUMNS}""",
        (grace_seconds, grace_seconds, grace_seconds, new_hash, service_id),
    )
    row = await cur.fetchone()
    return _service(row) if row else None


async def revoke_previous_secret(conn: AsyncConnection[Any], service_id: str) -> Service | None:
    cur = await conn.execute(
        f"""UPDATE identity.services
               SET previous_secret_sha256 = NULL, previous_secret_expires_at = NULL, updated_at = now()
             WHERE id = %s RETURNING {_COLUMNS}""",
        (service_id,),
    )
    row = await cur.fetchone()
    return _service(row) if row else None


async def invalidate_tickets(conn: AsyncConnection[Any], service_id: str) -> int:
    """Spends every unredeemed ticket that involves the service, as its source or its destination."""
    cur = await conn.execute(
        """UPDATE identity.handoff_tickets SET consumed_at = now()
            WHERE consumed_at IS NULL AND (source_service = %s OR target_service = %s)""",
        (service_id, service_id),
    )
    return cur.rowcount


# --------------------------------------------------------------------------- seeding from IDENTITY_SERVICES


@dataclass(frozen=True, slots=True)
class SeedResult:
    inserted: list[str]
    drifted: list[str]


async def bootstrap(conn: AsyncConnection[Any], seed: Registry) -> SeedResult:
    """Inserts services from the environment that the database does not have. Never overwrites a database row.

    The database is the source of truth once a service is in it. A seed entry that now differs (another URL, secret or
    status) is reported, not applied: change it in the developer portal, then drop it from IDENTITY_SERVICES.
    """
    existing = {s.id: s for s in await list_all(conn)}
    inserted: list[str] = []
    drifted: list[str] = []
    for service in seed.services:
        current = existing.get(service.id)
        if current is None:
            try:
                await insert(
                    conn,
                    {
                        "id": service.id,
                        "display_name": service.display_name,
                        "description": service.description,
                        "owner_team": service.owner_team,
                        "environment": service.environment,
                        "base_url": service.base_url,
                        "callback_path": service.callback_path,
                        "roles": service.roles,
                        "return_path_prefixes": service.return_path_prefixes,
                        "session_seconds": service.session_seconds,
                    },
                    secret_sha256=service.secret_sha256,
                    status="active" if service.enabled else "disabled",
                    source="bootstrap",
                    owner_user_id=None,
                    created_by=None,
                )
            except Conflict as exc:
                log.error("IDENTITY_SERVICES entry %r conflicts on %s with a registered service", service.id, exc.field)
                drifted.append(service.id)
                continue
            inserted.append(service.id)
        elif (current.base_url, current.secret_sha256, current.enabled) != (
            service.base_url,
            service.secret_sha256,
            service.enabled,
        ):
            drifted.append(service.id)
    if drifted:
        log.warning(
            "IDENTITY_SERVICES differs from the database for %s: the database wins; change them in the developer portal",
            ", ".join(drifted),
        )
    return SeedResult(inserted, drifted)


# --------------------------------------------------------------------------- developer grants


@dataclass(frozen=True, slots=True)
class Grant:
    user_id: UUID
    email: str
    environments: tuple[str, ...]


async def get_grant(conn: AsyncConnection[Any], user_id: UUID) -> tuple[str, ...]:
    cur = await conn.execute("SELECT environments FROM identity.developer_grants WHERE user_id = %s", (user_id,))
    row = await cur.fetchone()
    return tuple(row[0]) if row else ()


async def list_grants(conn: AsyncConnection[Any]) -> list[Grant]:
    cur = await conn.execute(
        """SELECT g.user_id, u.email, g.environments FROM identity.developer_grants g
             JOIN public.users u ON u.id = g.user_id ORDER BY u.email"""
    )
    return [Grant(row[0], row[1], tuple(row[2])) for row in await cur.fetchall()]


async def put_grant(conn: AsyncConnection[Any], user_id: UUID, environments: list[str], granted_by: UUID) -> None:
    await conn.execute(
        """INSERT INTO identity.developer_grants (user_id, environments, granted_by) VALUES (%s, %s, %s)
           ON CONFLICT (user_id) DO UPDATE SET environments = EXCLUDED.environments, granted_by = EXCLUDED.granted_by,
                                               granted_at = now()""",
        (user_id, environments, granted_by),
    )


async def delete_grant(conn: AsyncConnection[Any], user_id: UUID) -> bool:
    cur = await conn.execute("DELETE FROM identity.developer_grants WHERE user_id = %s", (user_id,))
    return cur.rowcount > 0
