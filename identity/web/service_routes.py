"""Service-to-service routes under /auth/service: the signed user feed (CONTRACT.md, "User feed").

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

There is no scheduler, so old events are purged from here: at most once an hour per instance, a bounded batch, on an
events request (and on demand with `identity-admin purge-user-events`).
"""

import logging
import re
import time
from typing import Any
from uuid import UUID

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from identity import registry_store, store, user_feed
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


async def _authorise(request: Request, conn: AsyncConnection[Any]) -> Service | JSONResponse:
    """The calling service, or the answer refusing it. Counts the request against the service's limit."""
    settings = _settings(request)
    credentials = _basic_credentials(request.headers.get("authorization"))
    registry: Registry = await registry_store.load_registry(conn, deployed=settings.deployed)
    service = registry.authenticate(*credentials) if credentials else None
    if service is None:
        if credentials and _is_inactive_service(registry, *credentials):
            # It proved it is that service, but a pending or disabled service reads nothing.
            return _error(403, "user_feed_not_allowed")
        return _error(401, "invalid_client", CHALLENGE)
    if service.id not in settings.user_feed_service_ids:
        return _error(403, "user_feed_not_allowed")
    key = f"feed:{service.id}"
    limit = {key: settings.user_feed_rate_limit}
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
