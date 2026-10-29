"""SSO hand-off routes under /auth (docs/sso-handoff.md).

* `GET /auth/services`: the services this person may open, for the switcher. Credentialed CORS, allowlisted origins.
* `POST /auth/handoff`: a signed-in browser on a registered service asks for a ticket to another registered service.
  Authenticated by the refresh cookie (read, never rotated); the source is the request's `Origin`, which must be a
  registered, **active** service's origin; the destination comes from the registry, never from the request.
* `POST /auth/handoff/redeem`: the destination's *backend* trades a ticket for the person's identity, proving itself
  with its service secret (HTTP Basic, `<service id>:<secret>`). No CORS: browsers cannot call it.

The registry is read from the database inside each of these requests (never from this process's memory), so disabling
a service, rotating its secret or changing its address applies to the next call on every identity-service instance.

Neither a token nor a ticket is ever logged: audit rows carry service ids only.
"""

import base64
import binascii
import hashlib
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from identity import handoff, registry_store, sessions, store
from identity.config import Settings
from identity.services import Registry, Service
from identity.web import cookies
from identity.web.security import cors_headers

router = APIRouter(prefix="/auth")

MAX_FIELD = 2048


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _pool(request: Request) -> AsyncConnectionPool:
    return request.app.state.pool


def _client(request: Request) -> tuple[str, str | None]:
    return (request.client.host if request.client else "unknown"), request.headers.get("user-agent")


def _error(status: int, code: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status, headers=headers)


def _basic_credentials(header: str | None) -> tuple[str, str] | None:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode()
    except (binascii.Error, UnicodeDecodeError):
        return None
    service_id, separator, secret = decoded.partition(":")
    return (service_id, secret) if separator and service_id and secret else None


def _is_inactive_service(registry: Registry, service_id: str, secret: str) -> bool:
    """Whether these are the valid credentials of a registered service that is not active."""
    service = next((s for s in registry.services if s.id == service_id and not s.enabled), None)
    return service is not None and service.accepts_secret(hashlib.sha256(secret.encode()).hexdigest())


# --------------------------------------------------------------------------- the browser side


@router.options("/handoff")
@router.options("/services")
async def preflight(request: Request) -> Response:
    cors = cors_headers(request, _settings(request))
    if cors is None:
        return Response(status_code=403)
    headers = {
        **cors,
        "Access-Control-Allow-Methods": "GET, POST",
        "Access-Control-Allow-Headers": "content-type",
        "Access-Control-Max-Age": "600",
    }
    return Response(status_code=204, headers=headers)


async def _session(
    request: Request, conn: AsyncConnection[Any]
) -> tuple[sessions.Peeked | None, dict[str, str] | None, Response | None]:
    """(session, cors headers, an error response when there is none). The cookie is read, not rotated."""
    settings = _settings(request)
    cors = cors_headers(request, settings)
    if cors is None:
        return None, None, _error(403, "origin")
    raw = request.cookies.get(cookies.cookie_name(cookies.REFRESH, settings))
    peeked = await sessions.peek(conn, raw, settings)
    if isinstance(peeked, sessions.Rejected):
        return None, cors, _error(401, peeked.reason, cors)
    return peeked, cors, None


def _listing(service: Service) -> dict[str, str]:
    return {
        "id": service.id,
        "display_name": service.display_name,
        "base_url": service.base_url,
        "environment": service.environment,
    }


@router.get("/services")
async def list_services(request: Request) -> Response:
    async with _pool(request).connection() as conn:
        peeked, cors, failure = await _session(request, conn)
        registry: Registry = await registry_store.load_registry(conn)
    if failure is not None or peeked is None:
        return failure or _error(401, "unknown")
    current = registry.by_origin(request.headers.get("origin"))
    body = {
        "current": current.id if current else None,
        "services": [_listing(s) for s in registry.visible_to(peeked.user.role)],
    }
    return JSONResponse(body, headers=cors)


@router.post("/handoff")
async def create_handoff(request: Request) -> Response:
    settings = _settings(request)
    async with _pool(request).connection() as conn:
        peeked, cors, failure = await _session(request, conn)
        registry: Registry = await registry_store.load_registry(conn)
    if failure is not None or peeked is None or cors is None:
        return failure or _error(401, "unknown")
    source = registry.by_origin(request.headers.get("origin"))
    if source is None:
        return _error(403, "source_not_registered", cors)
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        return _error(415, "content_type", cors)
    try:
        body: Any = await request.json()
    except ValueError:
        return _error(400, "body", cors)
    target_id = body.get("target") if isinstance(body, dict) else None
    return_to = body.get("return_to", "/") if isinstance(body, dict) else None
    if not isinstance(target_id, str) or not isinstance(return_to, str) or len(return_to) > MAX_FIELD:
        return _error(400, "body", cors)
    target = registry.get(target_id)
    # An unknown, disabled, pending or role-restricted destination all look the same to the caller.
    if target is None or not target.visible_to(peeked.user.role):
        return _error(403, "target_unavailable", cors)
    ip, agent = _client(request)
    async with _pool(request).connection() as conn:
        raw = await handoff.issue(
            conn,
            family_id=peeked.family_id,
            user_id=peeked.user.id,
            source=source.id,
            target=target.id,
            return_path=target.landing(return_to),
            seconds=settings.handoff_ticket_seconds,
        )
        if raw is not None:
            await store.audit(
                conn,
                "handoff_issued",
                user_id=peeked.user.id,
                ip=ip,
                user_agent=agent,
                metadata={"source": source.id, "target": target.id},
            )
    if raw is None:
        return _error(429, "too_many_tickets", {**cors, "Retry-After": str(settings.handoff_ticket_seconds)})
    return JSONResponse(
        {
            "ticket": raw,
            "redeem_url": target.redeem_url,
            "target": target.id,
            "expires_in": settings.handoff_ticket_seconds,
        },
        headers=cors,
    )


# --------------------------------------------------------------------------- the server side


@router.post("/handoff/redeem")
async def redeem_handoff(request: Request) -> Response:
    credentials = _basic_credentials(request.headers.get("authorization"))
    async with _pool(request).connection() as conn:
        registry: Registry = await registry_store.load_registry(conn)
    service = registry.authenticate(*credentials) if credentials else None
    if service is None:
        if credentials and _is_inactive_service(registry, *credentials):
            # The caller proved it is that service, so it may be told: it has been disabled (or is not yet approved).
            return _error(403, "service_disabled")
        return _error(401, "invalid_service", {"WWW-Authenticate": 'Basic realm="vetfab-handoff"'})
    try:
        body: Any = await request.json()
    except ValueError:
        return _error(400, "body")
    ticket = body.get("ticket") if isinstance(body, dict) else None
    if not isinstance(ticket, str):
        return _error(400, "body")
    ip, agent = _client(request)
    async with _pool(request).connection() as conn:
        outcome = await handoff.redeem(conn, ticket, service.id)
        source = registry.get(outcome.source_service) if isinstance(outcome, handoff.Redeemed) else None
        if isinstance(outcome, handoff.Redeemed) and source is None:
            # The service the ticket came from has been disabled since: the ticket is spent and refused.
            outcome = handoff.Refused("source_disabled")
        if isinstance(outcome, handoff.Refused):
            await store.audit(
                conn,
                "handoff_rejected",
                ip=ip,
                user_agent=agent,
                metadata={"service": service.id, "reason": outcome.reason},
            )
        else:
            await store.audit(
                conn,
                "handoff_redeemed",
                user_id=outcome.user_id,
                ip=ip,
                user_agent=agent,
                metadata={"source": outcome.source_service, "target": service.id},
            )
    if isinstance(outcome, handoff.Refused) or source is None:
        # One answer for every reason: a caller learns nothing about why (the audit log has it).
        return _error(400, "invalid_ticket")
    user_id: UUID = outcome.user_id
    return JSONResponse(
        {
            "user_id": str(user_id),
            "source_service": outcome.source_service,
            "source_origin": source.base_url,
            "return_path": service.landing(outcome.return_path),
        }
    )
