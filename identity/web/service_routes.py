"""Service-to-service routes under /auth/service: the signed user feed (CONTRACT.md, "User feed") and account status
changes requested by a product (CONTRACT.md, "Account status").

* `GET /auth/service/user-events?after&limit`: the change log, ascending by seq, with the retained bounds.
* `GET /auth/service/users/{id}`: one user's current snapshot (a consumer's first sight of an id).
* `GET /auth/service/users?after&limit`: every live user by id, for a reconcile, with the event head read first.

The caller is a registry service's *backend*: HTTP Basic `<service id>:<secret>`, checked exactly as
`POST /auth/handoff/redeem` checks it (the current secret, or the previous one inside its rotation grace). It must be
**active** and listed in IDENTITY_USER_FEED_SERVICES (empty: the feed is off). No CORS: browsers cannot call these.
Requests are rate-limited per service with the sign-in limiter's counters (`feed:<service id>`).

Every answer is `Cache-Control: no-store`. A success is `200 application/jwt`: a compact JWS signed with the
access-token key, header `typ: user-feed+jwt`, `aud` the calling service (identity/user_feed.py). Errors are JSON
`{"detail": {"code": ...}}`. Feed reads are not audited: a consumer polls every few seconds.

`POST /auth/service/users/{id}/status` is the one write: a product's backend asks, on behalf of one of its
administrators, for an account to be approved, rejected or suspended. Same credentials, but its own permission
(IDENTITY_ACCOUNT_STATUS_SERVICES, empty: off; being allowed the feed implies nothing here) and its own limit
(`status:<service id>`). It answers JSON, never touches an administrator's account, signs a rejected or suspended
account out as `identity-admin set-status` does, and writes identity.audit naming the service and the acting person.

There is no scheduler, so old events are purged from here: at most once an hour per instance, a bounded batch, on an
events request (and on demand with `identity-admin purge-user-events`).
"""

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from identity import registry_store, sessions, store, user_feed
from identity.config import Settings
from identity.keys import KeyRing
from identity.services import Registry, Service

# The same Basic parsing and inactive-service check as the hand-off redemption.
from identity.web.handoff_routes import _basic_credentials, _is_inactive_service

router = APIRouter(prefix="/auth/service")
log = logging.getLogger("identity")

NO_STORE = {"Cache-Control": "no-store"}
CHALLENGE = {"WWW-Authenticate": 'Basic realm="vetfab-identity"'}
RATE_WINDOW_SECONDS = 600
PURGE_INTERVAL_SECONDS = 3600
PURGE_BATCH = 5000
_DIGITS = re.compile(r"[0-9]{1,19}")
MAX_UUID_TEXT = 45
# What a product may ask for. Back to `pending` is an operator's reset (`identity-admin set-status`), not a product's.
REQUESTABLE_STATUSES: tuple[store.Status, ...] = ("approved", "rejected", "suspended")
STATUS_FIELDS = frozenset({"status", "actor_id", "reason"})
MAX_STATUS_BODY = 2048
MAX_REASON = 500


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _pool(request: Request) -> AsyncConnectionPool[Any]:
    return request.app.state.pool


def _keys(request: Request) -> KeyRing:
    return request.app.state.keys


def _error(status: int, code: str, headers: dict[str, str] | None = None, **extra: str) -> JSONResponse:
    return JSONResponse(
        {"detail": {"code": code, **extra}}, status_code=status, headers={**NO_STORE, **(headers or {})}
    )


class _BadParameter(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


def _integer(request: Request, name: str, *, default: int, low: int, high: int) -> int:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    if not _DIGITS.fullmatch(raw) or not low <= int(raw) <= high:
        raise _BadParameter(name)
    return int(raw)


def _uuid(raw: str | None, name: str) -> UUID:
    try:
        if raw is None or len(raw) > MAX_UUID_TEXT:
            raise ValueError(raw)
        return UUID(raw)
    except ValueError:
        raise _BadParameter(name) from None


@dataclass(frozen=True, slots=True)
class _Access:
    """One per-service permission: who holds it, what a caller without it is told, and its request limit."""

    allowed: frozenset[str]
    denied: str
    counter: str
    limit: int


def _feed_access(settings: Settings) -> _Access:
    return _Access(settings.user_feed_service_ids, "user_feed_not_allowed", "feed", settings.user_feed_rate_limit)


def _status_access(settings: Settings) -> _Access:
    return _Access(
        settings.account_status_service_ids, "account_status_not_allowed", "status", settings.account_status_rate_limit
    )


async def _authorise(
    request: Request, conn: AsyncConnection[Any], access: _Access | None = None
) -> Service | JSONResponse:
    """The calling service, or the answer refusing it. Counts the request against the service's limit."""
    settings = _settings(request)
    access = access or _feed_access(settings)
    credentials = _basic_credentials(request.headers.get("authorization"))
    registry: Registry = await registry_store.load_registry(conn, deployed=settings.deployed)
    service = registry.authenticate(*credentials) if credentials else None
    if service is None:
        if credentials and _is_inactive_service(registry, *credentials):
            # It proved it is that service, but a pending or disabled service reads nothing.
            return _error(403, access.denied)
        return _error(401, "invalid_client", CHALLENGE)
    if service.id not in access.allowed:
        return _error(403, access.denied)
    key = f"{access.counter}:{service.id}"
    limit = {key: access.limit}
    if await store.rate_limited(conn, limit, window_seconds=RATE_WINDOW_SECONDS):
        wait = await store.retry_after(conn, key, window_seconds=RATE_WINDOW_SECONDS)
        return _error(429, "too_many_requests", {"Retry-After": str(wait)})
    await store.record_failure(conn, [key], window_seconds=RATE_WINDOW_SECONDS)
    await conn.commit()  # the request counts even if it later fails
    return service


async def _purge_if_due(request: Request, conn: AsyncConnection[Any]) -> None:
    """Drops a bounded batch of expired events, at most once an hour per instance. Never fails the request."""
    state = request.app.state
    now = time.monotonic()
    if state.user_feed_purged_at is not None and now - state.user_feed_purged_at < PURGE_INTERVAL_SECONDS:
        return
    state.user_feed_purged_at = now  # claimed before the await, so concurrent requests do not purge twice
    days = _settings(request).user_events_retention_days
    try:
        removed = await user_feed.purge(conn, days, PURGE_BATCH)
        await conn.commit()
    except psycopg.Error:
        await conn.rollback()
        log.exception("could not purge expired user events; trying again in an hour")
        return
    if removed:
        log.info("purged %d user events older than %d days", removed, days)


def _document(request: Request, service: Service, kind: user_feed.Kind, body: dict[str, Any]) -> Response:
    token = user_feed.sign(_keys(request), _settings(request), service.id, kind, body)
    return Response(token, media_type="application/jwt", headers=NO_STORE)


@router.get("/user-events")
async def user_events(request: Request) -> Response:
    async with _pool(request).connection() as conn:
        caller = await _authorise(request, conn)
        if not isinstance(caller, Service):
            return caller
        try:
            after = _integer(request, "after", default=0, low=0, high=user_feed.MAX_SEQ)
            limit = _integer(request, "limit", default=user_feed.DEFAULT_EVENTS, low=1, high=user_feed.MAX_EVENTS)
        except _BadParameter as exc:
            return _error(422, "invalid_request", field=exc.name)
        await _purge_if_due(request, conn)
        body = await user_feed.read_events(conn, after, limit)
    return _document(request, caller, "user-events", body)


@router.get("/users/{user_id}")
async def user(request: Request, user_id: str) -> Response:
    async with _pool(request).connection() as conn:
        caller = await _authorise(request, conn)
        if not isinstance(caller, Service):
            return caller
        try:
            wanted = _uuid(user_id, "id")
        except _BadParameter as exc:
            return _error(422, "invalid_request", field=exc.name)
        snapshot = await user_feed.read_user(conn, wanted)
    return _document(request, caller, "user", {"user": snapshot})


@router.get("/users")
async def users(request: Request) -> Response:
    async with _pool(request).connection() as conn:
        caller = await _authorise(request, conn)
        if not isinstance(caller, Service):
            return caller
        try:
            raw_after = request.query_params.get("after")
            after = None if raw_after is None else _uuid(raw_after, "after")
            limit = _integer(request, "limit", default=user_feed.DEFAULT_USERS, low=1, high=user_feed.MAX_USERS)
        except _BadParameter as exc:
            return _error(422, "invalid_request", field=exc.name)
        body = await user_feed.read_users(conn, after, limit)
    return _document(request, caller, "users", body)


# --------------------------------------------------------------------------- account status (the one write)


async def _status_request(request: Request) -> tuple[store.Status, UUID, str | None]:
    """The wanted status, the acting person and the optional reason, or _BadParameter naming what is wrong."""
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise _BadParameter("content-type")
    raw = await request.body()
    if len(raw) > MAX_STATUS_BODY:
        raise _BadParameter("body")
    try:
        body = json.loads(raw)
    except ValueError:
        raise _BadParameter("body") from None
    if not isinstance(body, dict):
        raise _BadParameter("body")
    fields = cast(dict[str, Any], body)
    unknown = sorted(set(fields) - STATUS_FIELDS)
    if unknown:  # nothing else about an account is ever taken from a product: no email, role or password
        raise _BadParameter(unknown[0][:64])
    status = fields.get("status")
    if not isinstance(status, str) or status not in REQUESTABLE_STATUSES:
        raise _BadParameter("status")
    actor = fields.get("actor_id")
    actor_id = _uuid(actor if isinstance(actor, str) else None, "actor_id")
    reason = fields.get("reason")
    if reason is not None and (not isinstance(reason, str) or len(reason) > MAX_REASON):
        raise _BadParameter("reason")
    return cast(store.Status, status), actor_id, (reason.strip() or None) if reason else None


@router.post("/users/{user_id}/status")
async def set_user_status(request: Request, user_id: str) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        caller = await _authorise(request, conn, _status_access(settings))
        if not isinstance(caller, Service):
            return caller
        try:
            wanted = _uuid(user_id, "id")
            status, actor_id, reason = await _status_request(request)
        except _BadParameter as exc:
            return _error(422, "invalid_request", field=exc.name)
        if actor_id == wanted:
            return _error(409, "own_account")
        # The acting person must be an account in good standing here. Whether they administer the product is the
        # product's to decide (and the reason this permission is granted per service).
        actor = await store.get_user(conn, actor_id)
        if actor is None or actor.status != "approved":
            return _error(403, "actor_not_allowed")
        target = await store.lock_user(conn, wanted)
        if target is None:
            return _error(404, "user_not_found")
        meta: dict[str, Any] = {"via": "service", "service": caller.id, "from": target.status, "to": status}
        if reason:
            meta["reason"] = reason
        if target.role == "admin" or store.normalise_email(target.email) in settings.admin_email_list:
            # An administrator's account is changed by an operator on this host, never by a product.
            await store.audit(conn, "admin_denied", user_id=target.id, actor_id=actor.id, metadata=meta)
            log.warning("service %s asked to set an administrator account to %s; refused", caller.id, status)
            return _error(403, "admin_account")
        changed = target.status != status
        if changed:
            await store.set_status(conn, target.id, status)
        # A repeat changes nothing, but still leaves no session behind for an account that may not hold one.
        revoked = 0 if status in store.ACTIVE_STATUSES else await sessions.revoke_user(conn, target.id, "admin")
        if changed or revoked:
            meta["sessions_revoked"] = revoked
            await store.audit(conn, "status_change", user_id=target.id, actor_id=actor.id, metadata=meta)
    return JSONResponse(
        {
            "user": {"id": str(target.id), "status": status},
            "previous_status": target.status,
            "changed": changed,
            "sessions_revoked": revoked,
        },
        headers=NO_STORE,
    )
