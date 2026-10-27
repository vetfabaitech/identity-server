"""The developer portal's API: `/auth/admin/*` (docs/developer-portal.md).

It sits under `/auth` because the identity service's refresh cookie is scoped to that path; the cookie *is* the
credential. There is no portal login of its own: a person signs in with the existing identity service, and every
request here re-derives who they are from that session, then decides what they may do **in this module**. The page at
`/developer/services` is a convenience; none of these checks is made, or can be skipped, there.

Who may do what (an account is "active": pending or approved, with a live session):

| | administrator (`users.role = admin`, approved) | developer (a grant, `local`/`staging` only) | anyone else |
|---|---|---|---|
| register a service | any environment | only in a granted environment, never production | no |
| see services | all | only the ones they own (others answer 404, not 403: no enumeration) | no |
| edit name, description, team, visibility, return paths, session length | yes | own | no |
| edit address, callback path, environment | any time (production: typed confirmation) | own, **only while pending** | no |
| activate (`enable`) | yes | **no** | no |
| disable | yes | own | no |
| rotate / revoke secrets | yes | own | no |
| grant or revoke developers | yes | no | no |

Activating is administrator-only on purpose: an active service's address joins the list of origins that are handed
access tokens at sign-in, so whoever can activate can receive those tokens.

Owner, status and role are never read from a request body: unknown fields are refused. Secrets are generated here,
stored only as SHA-256, shown once in the response that creates them, and never logged or returned again.
"""

import hashlib
import ipaddress
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from identity import registry_store, sessions, store
from identity.config import Settings
from identity.registry_store import Conflict
from identity.services import DEVELOPER_ENVIRONMENTS, ENVIRONMENTS, RegistryError, Service, clean_fields
from identity.store import AuditAction
from identity.web import cookies
from identity.web.security import origin_of

router = APIRouter(prefix="/auth/admin")

NO_CACHE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
CREATE_FIELDS = frozenset(
    {
        "id",
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
# Fields that decide where tokens and tickets go. Owners may change them only while a service is pending.
TRUSTED_FIELDS = frozenset({"base_url", "callback_path", "environment"})
ENV_NAMES = {"local": "development", "staging": "staging", "production": "production"}
MAX_PAGE_SIZE = 100


class ApiError(Exception):
    def __init__(self, status: int, code: str, extra: dict[str, Any] | None = None) -> None:
        super().__init__(code)
        self.status, self.code, self.extra = status, code, extra or {}


async def api_error_handler(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, ApiError)
    return JSONResponse({"error": exc.code, **exc.extra}, status_code=exc.status, headers=NO_CACHE)


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _pool(request: Request) -> AsyncConnectionPool[Any]:
    return request.app.state.pool


def _reply(body: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=NO_CACHE)


# --------------------------------------------------------------------------- who is calling


@dataclass(frozen=True, slots=True)
class Actor:
    user: store.User
    is_admin: bool
    environments: tuple[str, ...]  # developer grant (admins may use every environment)
    ip: str
    agent: str | None

    @property
    def can_register(self) -> tuple[str, ...]:
        return ("local", "staging", "production") if self.is_admin else self.environments

    def owns(self, service: Service) -> bool:
        return service.owner_user_id == self.user.id


def _own_origin(settings: Settings) -> str | None:
    return origin_of(settings.issuer)


async def _begin(
    request: Request, conn: AsyncConnection[Any], *, mutate: bool, admin_only: bool = False, secret_op: bool = False
) -> Actor:
    """Authenticates the caller from the identity session and applies the rules every request here shares."""
    settings = _settings(request)
    raw = request.cookies.get(cookies.cookie_name(cookies.REFRESH, settings))
    peeked = await sessions.peek(conn, raw, settings)
    if isinstance(peeked, sessions.Rejected):
        raise ApiError(401, "not_signed_in")
    user = peeked.user
    is_admin = user.role == "admin" and user.status == "approved"
    environments = () if is_admin else await registry_store.get_grant(conn, user.id)
    ip = request.client.host if request.client else "unknown"
    agent = request.headers.get("user-agent")
    actor = Actor(user, is_admin, environments, ip, agent)
    if not is_admin and not environments:
        await _denied(conn, settings, actor, request, mutate)
        raise ApiError(403, "not_authorised")
    if admin_only and not is_admin:
        await _denied(conn, settings, actor, request, mutate)
        raise ApiError(403, "administrator_only")
    if mutate:
        # CSRF: the session is a cookie, so a state-changing call must come from this host's own pages.
        own = _own_origin(settings)
        fetch_site = request.headers.get("sec-fetch-site")
        if own is None or request.headers.get("origin") != own or fetch_site not in (None, "same-origin"):
            raise ApiError(403, "csrf")
        limit = max(1, settings.admin_rate_limit // 6) if secret_op else settings.admin_rate_limit
        key = f"{'secret' if secret_op else 'admin'}:{user.id}"
        window = settings.rate_limit_window_seconds
        if await store.rate_limited(conn, {key: limit}, window_seconds=window):
            raise ApiError(429, "too_many_requests")
        await store.record_failure(conn, [key], window_seconds=window)
        await conn.commit()  # attempts count even when the request later fails
    return actor


async def _denied(conn: AsyncConnection[Any], settings: Settings, actor: Actor, request: Request, mutate: bool) -> None:
    """Records a refused attempt (state-changing ones always, until a person has been refused 10 times in a window)."""
    key, window = f"denied:{actor.user.id}", settings.rate_limit_window_seconds
    if not mutate or await store.rate_limited(conn, {key: 10}, window_seconds=window):
        return
    await store.record_failure(conn, [key], window_seconds=window)
    meta = {"method": request.method, "path": request.url.path}
    await store.audit(conn, "admin_denied", user_id=actor.user.id, ip=actor.ip, user_agent=actor.agent, metadata=meta)
    await conn.commit()  # the denial is recorded even though the request fails


async def _body(request: Request, allowed: frozenset[str]) -> dict[str, Any]:
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise ApiError(415, "content_type")
    try:
        body = await request.json()
    except ValueError:
        raise ApiError(400, "body") from None
    if not isinstance(body, dict):
        raise ApiError(400, "body")
    unknown = sorted(str(k) for k in body if k not in allowed)
    if unknown:  # owner, status, role, secret hashes... are never taken from a request
        raise ApiError(400, "unknown_field", {"fields": unknown[:10]})
    return body


async def _audit(
    conn: AsyncConnection[Any], action: AuditAction, actor: Actor, service_id: str | None, **details: Any
) -> None:
    metadata = {k: v for k, v in details.items() if v is not None}
    if service_id:
        metadata["service"] = service_id
    await store.audit(
        conn,
        action,
        user_id=actor.user.id,
        actor_id=actor.user.id,
        ip=actor.ip,
        user_agent=actor.agent,
        metadata=metadata,
    )


# --------------------------------------------------------------------------- what a service looks like to a caller


def _permissions(actor: Actor, service: Service) -> dict[str, bool]:
    owner = actor.owns(service)
    manage = actor.is_admin or owner
    pending = service.status == "pending"
    return {
        "edit": manage,
        "edit_trusted": actor.is_admin or (owner and pending),
        "enable": actor.is_admin and service.status != "active",
        "disable": manage and service.status != "disabled",
        "rotate_secret": manage,
        "validate": manage,
    }


def _view(service: Service, actor: Actor, owners: dict[UUID, str]) -> dict[str, Any]:
    now_epoch = time.time()
    grace = service.previous_secret_expires_at
    return {
        "id": service.id,
        "display_name": service.display_name,
        "description": service.description,
        "owner_team": service.owner_team,
        "owner": owners.get(service.owner_user_id) if service.owner_user_id else None,
        "environment": service.environment,
        "base_url": service.base_url,
        "callback_path": service.callback_path,
        "redeem_url": service.redeem_url,
        "roles": list(service.roles),
        "return_path_prefixes": list(service.return_path_prefixes),
        "session_seconds": service.session_seconds,
        "status": service.status,
        "source": service.source,
        "previous_secret_valid_until": grace if grace and grace > now_epoch else None,
        "created_at": service.created_at.isoformat() if service.created_at else None,
        "updated_at": service.updated_at.isoformat() if service.updated_at else None,
        "permissions": _permissions(actor, service),
    }


async def _visible(conn: AsyncConnection[Any], actor: Actor) -> list[Service]:
    services = await registry_store.list_all(conn)
    return services if actor.is_admin else [s for s in services if actor.owns(s)]


async def _load(conn: AsyncConnection[Any], actor: Actor, service_id: str) -> Service:
    service = await registry_store.get(conn, service_id)
    # A service someone else owns is "not found", not "forbidden": identifiers cannot be probed.
    if service is None or not (actor.is_admin or actor.owns(service)):
        raise ApiError(404, "not_found")
    return service


async def _refresh(request: Request) -> None:
    """After a change has committed: this instance's origin allowlist catches up at once (others within the TTL)."""
    await request.app.state.registry_cache.refresh(_pool(request))


def _confirm(body: dict[str, Any], service: Service, *, required: bool) -> None:
    if (required or service.environment == "production") and body.get("confirm") != service.id:
        raise ApiError(400, "confirmation_required", {"expected": "the service id"})


def _new_secret() -> tuple[str, str]:
    secret = secrets.token_urlsafe(32)
    return secret, hashlib.sha256(secret.encode()).hexdigest()


# --------------------------------------------------------------------------- validation


def _check(code: str, level: str, message: str) -> dict[str, str]:
    return {"code": code, "level": level, "message": message}


def _host_checks(fields: dict[str, Any]) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    host = urlsplit(fields["base_url"]).hostname or ""
    loopback = host in ("localhost", "127.0.0.1", "::1")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if fields["environment"] == "production" and (
        loopback or (address and (address.is_private or address.is_loopback))
    ):
        checks.append(
            _check(
                "production_private_host",
                "error",
                "A production service cannot live on localhost or a private address.",
            )
        )
    elif fields["environment"] == "local" and not loopback:
        checks.append(_check("local_not_loopback", "warning", "A local service is expected on localhost."))
    elif address is not None:
        checks.append(
            _check("ip_host", "warning", "The address is a bare IP; use a host name so https certificates work.")
        )
    return checks


async def _checks(
    conn: AsyncConnection[Any], settings: Settings, raw: dict[str, Any], *, existing: Service | None
) -> tuple[list[dict[str, str]], dict[str, Any] | None]:
    """Everything a configuration must satisfy before it can be activated. Makes no network request of any kind."""
    checks: list[dict[str, str]] = []
    try:
        fields = clean_fields(raw, deployed=settings.deployed, label="service", require_secret_hash=False)
    except RegistryError as exc:
        return [_check("invalid_fields", "error", str(exc))], None
    checks.append(_check("fields", "ok", "Identifier, address, environment, paths and session length are well-formed."))
    others = [s for s in await registry_store.list_all(conn) if existing is None or s.id != existing.id]
    if existing is None and any(s.id == fields["id"] for s in others):
        checks.append(_check("id_taken", "error", "That service identifier is already registered."))
    if any(s.base_url == fields["base_url"] for s in others):
        checks.append(_check("origin_taken", "error", "That address is already registered to another service."))
    if fields["base_url"] == _own_origin(settings):
        checks.append(
            _check("identity_host", "error", "The identity service itself cannot be registered as a service.")
        )
    checks += _host_checks(fields)
    if fields["environment"] == "production":
        checks.append(_check("https", "ok", "Production address uses https."))
    checks.append(
        _check(
            "protocol",
            "info",
            f"Tickets are posted by the browser to {fields['base_url']}{fields['callback_path']}; the service's backend redeems them "
            "with its secret. Its address is trusted for sign-in only once an administrator activates it.",
        )
    )
    checks.append(
        _check("no_network", "info", "Validation checks configuration only; no request is made to the address.")
    )
    return checks, fields


def _ok(checks: list[dict[str, str]]) -> bool:
    return not any(c["level"] == "error" for c in checks)


# --------------------------------------------------------------------------- endpoints: who am I


@router.get("/me")
async def me(request: Request) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=False)
    return _reply(
        {
            "user": {"id": str(actor.user.id), "email": actor.user.email, "name": actor.user.display_name},
            "is_admin": actor.is_admin,
            "register_environments": list(actor.can_register),
            "limits": {
                "ticket_seconds": settings.handoff_ticket_seconds,
                "rotation_grace_seconds": settings.secret_rotation_grace_seconds,
            },
            "auth_url": _own_origin(settings),
            "deployed": settings.deployed,
        }
    )


# --------------------------------------------------------------------------- endpoints: services


@router.get("/services")
async def list_services(
    request: Request, q: str = "", status: str = "", environment: str = "", page: int = 1, page_size: int = 20
) -> Response:
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=False)
        services = await _visible(conn, actor)
        owners = await registry_store.owner_emails(conn, {s.owner_user_id for s in services if s.owner_user_id})
    needle = q.strip().lower()[:100]
    selected = [
        s
        for s in services
        if (not status or s.status == status)
        and (not environment or s.environment == environment)
        and (
            not needle
            or needle in s.id
            or needle in s.display_name.lower()
            or needle in s.owner_team.lower()
            or needle in (owners.get(s.owner_user_id, "") if s.owner_user_id else "").lower()
        )
    ]
    size = min(max(page_size, 1), MAX_PAGE_SIZE)
    number = max(page, 1)
    window = selected[(number - 1) * size : number * size]
    return _reply(
        {
            "items": [_view(s, actor, owners) for s in window],
            "total": len(selected),
            "page": number,
            "page_size": size,
            "counts": {st: sum(1 for s in services if s.status == st) for st in ("pending", "active", "disabled")},
        }
    )


@router.post("/services/validate")
async def validate_draft(request: Request) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True)
        body = await _body(request, CREATE_FIELDS)
        _require_environment(actor, body, settings)
        checks, _ = await _checks(conn, settings, body, existing=None)
    return _reply({"ok": _ok(checks), "checks": checks})


def _require_environment(actor: Actor, body: dict[str, Any], settings: Settings) -> None:
    environment = body.get("environment", "production" if settings.deployed else "local")
    if environment not in ENVIRONMENTS or environment not in actor.can_register:
        raise ApiError(403, "environment_not_permitted", {"permitted": list(actor.can_register)})


@router.post("/services")
async def register_service(request: Request) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True, secret_op=True)
        body = await _body(request, CREATE_FIELDS)
        _require_environment(actor, body, settings)
        checks, fields = await _checks(conn, settings, body, existing=None)
        if fields is None or not _ok(checks):
            raise ApiError(422, "validation_failed", {"checks": checks})
        secret, digest = _new_secret()
        try:
            # Always `pending`: an administrator reviews and activates. Nothing a request says sets owner or status.
            service = await registry_store.insert(
                conn, fields, secret_sha256=digest, status="pending", source="managed",
                owner_user_id=actor.user.id, created_by=actor.user.id,
            )  # fmt: skip
        except Conflict as exc:
            raise ApiError(409, "id_taken" if exc.field == "id" else "origin_taken") from None
        await _audit(conn, "service_created", actor, service.id, environment=service.environment)
        await _audit(conn, "service_secret_issued", actor, service.id, reason="registration")
        owners = {actor.user.id: actor.user.email}
        view = _view(service, actor, owners)
    await _refresh(request)
    return _reply({"service": view, "secret": secret, "secret_shown_once": True, "checks": checks}, 201)


@router.get("/services/{service_id}")
async def get_service(request: Request, service_id: str) -> Response:
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=False)
        service = await _load(conn, actor, service_id)
        owners = await registry_store.owner_emails(conn, {service.owner_user_id} if service.owner_user_id else set())
    return _reply({"service": _view(service, actor, owners)})


PATCH_FIELDS = CREATE_FIELDS - {"id"} | {"confirm"}


@router.patch("/services/{service_id}")
async def update_service(request: Request, service_id: str) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True)
        service = await _load(conn, actor, service_id)
        body = await _body(request, PATCH_FIELDS)
        changes = {k: v for k, v in body.items() if k != "confirm"}
        if not changes:
            raise ApiError(400, "no_changes")
        trusted = sorted(set(changes) & TRUSTED_FIELDS)
        if trusted and not _permissions(actor, service)["edit_trusted"]:
            # A developer cannot move a service that has been approved, or point it somewhere else.
            raise ApiError(403, "trusted_fields_locked", {"fields": trusted})
        if changes.get("environment") is not None and changes["environment"] not in actor.can_register:
            raise ApiError(403, "environment_not_permitted", {"permitted": list(actor.can_register)})
        if trusted and service.status == "active":
            _confirm(body, service, required=True)
        merged = {
            "id": service.id, "display_name": service.display_name, "description": service.description,
            "owner_team": service.owner_team, "environment": service.environment, "base_url": service.base_url,
            "callback_path": service.callback_path, "roles": list(service.roles),
            "return_path_prefixes": list(service.return_path_prefixes), "session_seconds": service.session_seconds,
            **changes,
        }  # fmt: skip
        checks, fields = await _checks(conn, settings, merged, existing=service)
        if fields is None or not _ok(checks):
            raise ApiError(422, "validation_failed", {"checks": checks})
        try:
            updated = await registry_store.update(conn, service.id, {k: fields[k] for k in changes})
        except Conflict:
            raise ApiError(409, "origin_taken") from None
        assert updated is not None
        spent = await registry_store.invalidate_tickets(conn, service.id) if trusted else 0
        await _audit(conn, "service_updated", actor, service.id, fields=sorted(changes), tickets_spent=spent or None)
        owners = await registry_store.owner_emails(conn, {updated.owner_user_id} if updated.owner_user_id else set())
        view = _view(updated, actor, owners)
    await _refresh(request)
    return _reply({"service": view, "checks": checks})


@router.post("/services/{service_id}/validate")
async def validate_service(request: Request, service_id: str) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True)
        service = await _load(conn, actor, service_id)
        checks, _ = await _checks(conn, settings, _as_fields(service), existing=service)
    return _reply({"ok": _ok(checks), "checks": checks})


def _as_fields(service: Service) -> dict[str, Any]:
    return {
        "id": service.id, "display_name": service.display_name, "description": service.description,
        "owner_team": service.owner_team, "environment": service.environment, "base_url": service.base_url,
        "callback_path": service.callback_path, "roles": list(service.roles),
        "return_path_prefixes": list(service.return_path_prefixes), "session_seconds": service.session_seconds,
    }  # fmt: skip


@router.post("/services/{service_id}/enable")
async def enable_service(request: Request, service_id: str) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True, admin_only=True)
        service = await _load(conn, actor, service_id)
        body = await _body(request, frozenset({"confirm"}))
        _confirm(body, service, required=False)
        if service.status == "active":
            raise ApiError(409, "already_active")
        checks, _ = await _checks(conn, settings, _as_fields(service), existing=service)
        if not _ok(checks):
            raise ApiError(422, "validation_failed", {"checks": checks})
        updated = await registry_store.set_status(conn, service.id, "active", actor.user.id)
        assert updated is not None
        await _audit(conn, "service_status_changed", actor, service.id, previous=service.status, status="active")
        owners = await registry_store.owner_emails(conn, {updated.owner_user_id} if updated.owner_user_id else set())
        view = _view(updated, actor, owners)
    await _refresh(request)
    return _reply({"service": view})


@router.post("/services/{service_id}/disable")
async def disable_service(request: Request, service_id: str) -> Response:
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True)
        service = await _load(conn, actor, service_id)
        body = await _body(request, frozenset({"confirm"}))
        _confirm(body, service, required=False)
        if service.status == "disabled":
            raise ApiError(409, "already_disabled")
        updated = await registry_store.set_status(conn, service.id, "disabled", actor.user.id)
        assert updated is not None
        # Tickets already issued from or to it die with it. Accounts and application data are not touched.
        spent = await registry_store.invalidate_tickets(conn, service.id)
        await _audit(
            conn,
            "service_status_changed",
            actor,
            service.id,
            previous=service.status,
            status="disabled",
            tickets_spent=spent,
        )
        owners = await registry_store.owner_emails(conn, {updated.owner_user_id} if updated.owner_user_id else set())
        view = _view(updated, actor, owners)
    await _refresh(request)
    return _reply({"service": view, "tickets_spent": spent})


@router.post("/services/{service_id}/rotate-secret")
async def rotate_secret(request: Request, service_id: str) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True, secret_op=True)
        service = await _load(conn, actor, service_id)
        body = await _body(request, frozenset({"confirm", "revoke_old"}))
        _confirm(body, service, required=True)  # rotating always asks for the service id to be typed
        revoke_old = body.get("revoke_old", False)
        if not isinstance(revoke_old, bool):
            raise ApiError(400, "body")
        grace = 0 if revoke_old else settings.secret_rotation_grace_seconds
        secret, digest = _new_secret()
        updated = await registry_store.rotate_secret(conn, service.id, digest, grace)
        assert updated is not None
        await _audit(conn, "service_secret_rotated", actor, service.id, previous_valid_seconds=grace)
        if revoke_old:
            await _audit(conn, "service_secret_revoked", actor, service.id, which="previous")
        owners = await registry_store.owner_emails(conn, {updated.owner_user_id} if updated.owner_user_id else set())
        view = _view(updated, actor, owners)
    return _reply({"service": view, "secret": secret, "secret_shown_once": True, "previous_valid_seconds": grace})


@router.post("/services/{service_id}/revoke-previous-secret")
async def revoke_previous(request: Request, service_id: str) -> Response:
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True, secret_op=True)
        service = await _load(conn, actor, service_id)
        body = await _body(request, frozenset({"confirm"}))
        _confirm(body, service, required=True)
        updated = await registry_store.revoke_previous_secret(conn, service.id)
        assert updated is not None
        await _audit(conn, "service_secret_revoked", actor, service.id, which="previous")
        owners = await registry_store.owner_emails(conn, {updated.owner_user_id} if updated.owner_user_id else set())
        view = _view(updated, actor, owners)
    return _reply({"service": view})


@router.get("/services/{service_id}/activity")
async def activity(request: Request, service_id: str) -> Response:
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=False)
        service = await _load(conn, actor, service_id)
        cur = await conn.execute(
            """SELECT a.at, a.action, u.email, a.metadata FROM identity.audit a
                 LEFT JOIN public.users u ON u.id = a.actor_id
                WHERE a.metadata->>'service' = %s OR a.metadata->>'source' = %s OR a.metadata->>'target' = %s
                ORDER BY a.id DESC LIMIT 50""",
            (service.id, service.id, service.id),
        )
        rows = await cur.fetchall()
    events = [{"at": r[0].isoformat(), "action": r[1], "actor": r[2], "details": r[3]} for r in rows]
    return _reply({"events": events})


# --------------------------------------------------------------------------- integration configuration


def integration_config(service: Service, settings: Settings) -> dict[str, Any]:
    """The setup for a service, built from the adapter's real configuration keys. Holds no secret of any kind."""
    auth_url = _own_origin(settings) or ""
    variables: list[dict[str, Any]] = [
        {"key": "VETFAB_AUTH_URL", "value": auth_url, "origin": "portal", "note": "The identity service's origin."},
        {"key": "VETFAB_ENVIRONMENT", "value": ENV_NAMES[service.environment], "origin": "portal",
         "note": "staging and production refuse plain-http URLs."},
        {"key": "VETFAB_SERVICE_ID", "value": service.id, "origin": "portal", "note": "This service's id in the registry."},
        {"key": "VETFAB_SERVICE_SECRET", "value": None, "origin": "secret",
         "placeholder": "<shown once when the service is registered or its secret rotated>",
         "note": "Server-side only. The identity service keeps only its hash."},
        {"key": "VETFAB_SESSION_SECRET", "value": None, "origin": "generate",
         "placeholder": "<generate: openssl rand -base64 48>",
         "note": "You generate this; it must be unique to this service and never shared or committed."},
        {"key": "VETFAB_APP_URL", "value": service.base_url, "origin": "portal",
         "note": "This service's own origin, exactly as registered."},
        {"key": "VETFAB_SESSION_SECONDS", "value": str(service.session_seconds), "origin": "portal",
         "note": "How long this service's own session lasts (60 to 3600)."},
        {"key": "VETFAB_CLIENT_ID", "value": service.id, "origin": "portal", "optional": True,
         "note": "A label for logs; not a credential."},
    ]  # fmt: skip
    if settings.issuer != f"{auth_url}/auth":
        variables.append(
            {
                "key": "VETFAB_AUTH_ISSUER",
                "value": settings.issuer,
                "origin": "portal",
                "note": "Differs from the default.",
            }
        )
    if settings.audience != "vetfab":
        variables.append(
            {
                "key": "VETFAB_AUTH_AUDIENCE",
                "value": settings.audience,
                "origin": "portal",
                "note": "Differs from the default.",
            }
        )
    https = service.base_url.startswith("https://")
    readiness = [
        {"id": "registered", "label": "Registered", "state": "done"},
        {"id": "approved", "label": "Approved and activated by an administrator",
         "state": "done" if service.status == "active" else "todo"},
        {"id": "https", "label": "Served over https", "state": "done" if https else ("todo" if service.environment != "local" else "n/a")},
        {"id": "secret", "label": "Redemption secret installed in the service's server-side secret store", "state": "manual"},
        {"id": "session_secret", "label": "Unique VETFAB_SESSION_SECRET generated and installed", "state": "manual"},
        {"id": "migration", "label": "Identity migrations applied (0005) on the identity deployment", "state": "manual"},
        {"id": "tests", "label": "Login, handoff in both directions, logout and permission checks pass", "state": "manual"},
        {"id": "browser", "label": "Verified in a real browser against this environment", "state": "manual"},
    ]  # fmt: skip
    return {
        "service": {
            "id": service.id,
            "environment": service.environment,
            "base_url": service.base_url,
            "status": service.status,
        },
        "variables": variables,
        "backend": {
            "package": "vetfab-identity-adapter",
            "install": 'pip install "./sdk/python[fastapi]"  # from the identity repository; not yet on a package index',
            "code": (
                "adapter_config = AdapterConfig.from_env()\n"
                "handoff_config = HandoffConfig.from_env(adapter_config, os.environ)\n"
                "sessions = SessionCookie(handoff_config)\n"
                "guard = IdentityGuard(IdentityAdapter(adapter_config), load_user, sessions=sessions, app_origin=handoff_config.app_url)\n"
                "app.include_router(handoff_router(HandoffRedeemer(adapter_config, handoff_config), sessions, load_user,\n"
                f"                                  app_origin=handoff_config.app_url, callback_path={service.callback_path!r}))"
            ),
        },
        "frontend": {
            "package": "@vetfab/identity-adapter",
            "install": "cd sdk/js && npm ci && npm run build   # then depend on file:<path>/sdk/js; the package is private",
            "code": (
                f"const client = createIdentityClient({{ authUrl: {auth_url!r}, sessionUrl: '/handoff/session', "
                "sessionLogoutUrl: '/handoff/logout' });\n"
                "const handoff = createHandoffClient(client);\n"
                f'<VetfabServiceSwitcher handoff={{handoff}} currentService={service.id!r} returnTo="/" />'
            ),
        },
        "local_test": [
            {
                "step": "Validate the configuration loads",
                "command": "python -c \"import os; from vetfab_identity_adapter import AdapterConfig, HandoffConfig; a = AdapterConfig.from_env(); HandoffConfig.from_env(a, os.environ); print('configuration ok')\"",
            },
            {
                "step": "Run the service and sign in through the identity service",
                "command": "uvicorn main:app --port <your port>",
            },
            {
                "step": "Check an unregistered origin is refused",
                "command": "curl -si -X POST -H 'Origin: https://evil.example' -H 'Content-Type: application/json' -d '{\"target\":\"x\"}' <identity>/auth/handoff   # expect 401/403",
            },
            {
                "step": "Hand off from another service and back",
                "command": "open the other service, choose this one in the switcher; then the reverse",
            },
            {
                "step": "Confirm your own authorisation applies",
                "command": "a person your load_user does not know must get 403, not a session",
            },
        ],  # fmt: skip
        "readiness": readiness,
        "production_ready": False,  # never inferred from registration: the manual items need a person's sign-off
    }


@router.get("/services/{service_id}/integration-config")
async def get_integration_config(request: Request, service_id: str) -> Response:
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=False)
        service = await _load(conn, actor, service_id)
    return _reply(integration_config(service, _settings(request)))


# --------------------------------------------------------------------------- developers (administrators only)


@router.get("/developers")
async def list_developers(request: Request) -> Response:
    async with _pool(request).connection() as conn:
        await _begin(request, conn, mutate=False, admin_only=True)
        grants = await registry_store.list_grants(conn)
    return _reply(
        {
            "developers": [
                {"user_id": str(g.user_id), "email": g.email, "environments": list(g.environments)} for g in grants
            ]
        }
    )


@router.put("/developers")
async def grant_developer(request: Request) -> Response:
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True, admin_only=True)
        body = await _body(request, frozenset({"email", "environments"}))
        email, environments = body.get("email"), body.get("environments")
        if (
            not isinstance(email, str)
            or not isinstance(environments, list)
            or not environments
            or any(e not in DEVELOPER_ENVIRONMENTS for e in environments)
        ):
            raise ApiError(400, "body", {"environments": "a non-empty list drawn from local, staging"})
        user = await store.find_user_by_email(conn, email[:320])
        if user is None or not user.active:
            raise ApiError(404, "user_not_found")
        await registry_store.put_grant(conn, user.id, sorted(set(environments)), actor.user.id)
        await _audit(conn, "developer_granted", actor, None, user=str(user.id), environments=sorted(set(environments)))
    return _reply({"user_id": str(user.id), "email": user.email, "environments": sorted(set(environments))})


@router.delete("/developers/{user_id}")
async def revoke_developer(request: Request, user_id: str) -> Response:
    try:
        target = UUID(user_id)
    except ValueError:
        raise ApiError(404, "not_found") from None
    async with _pool(request).connection() as conn:
        actor = await _begin(request, conn, mutate=True, admin_only=True)
        if not await registry_store.delete_grant(conn, target):
            raise ApiError(404, "not_found")
        await _audit(conn, "developer_revoked", actor, None, user=str(target))
    return _reply({"revoked": True})
