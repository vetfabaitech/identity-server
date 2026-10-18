"""Browser-facing protections: same-origin checks for state-changing posts, security headers, a body-size limit.

`same_origin` ports apps/web/src/lib/auth/origin.ts: `Origin` must be present and be the identity service's own
origin or the default app origin, with `Sec-Fetch-Site: same-origin` once deployed. Sign-out alone also accepts the
other IDENTITY_APP_ORIGINS (the IDE on demo.vetfab.ai), which are `same-site` by construction (spec SI-3, §4).
"""

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request

from identity.config import Settings

MAX_BODY_BYTES = 16 * 1024

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def same_origin(request: Request, settings: Settings, *, allow_siblings: bool = False) -> bool:
    """Whether a state-changing POST comes from this deployment's own pages.

    The service's own origin and the default app origin (the LMS, the same origin once deployed) are accepted as
    before. `allow_siblings` also accepts the other IDENTITY_APP_ORIGINS, which post same-site by construction; only
    sign-out uses it. Sign-in forms never do: a sibling product may receive tokens for its user, but must not choose
    which account the shared session belongs to (login CSRF).
    """
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return False
    sender = origin_of(origin)
    if sender in {settings.app_origin, origin_of(settings.issuer)}:
        allowed_sites = {"same-origin"} if settings.deployed else {"same-origin", "same-site"}
    elif allow_siblings and sender in settings.app_origin_list:
        allowed_sites = {"same-origin", "same-site"}
    else:
        return False
    fetch_site = request.headers.get("sec-fetch-site")
    return fetch_site is None or fetch_site in allowed_sites


def cors_headers(request: Request, settings: Settings) -> dict[str, str] | None:
    """Credentialed CORS headers for an allowlisted product origin, or None (spec SI-4 renewal)."""
    origin = request.headers.get("origin")
    if not origin or origin not in settings.app_origin_list:
        return None
    return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Vary": "Origin"}


def security_headers(settings: Settings) -> dict[str, str]:
    csp = (
        "default-src 'none'; style-src 'self'; img-src 'self'; "
        f"form-action 'self' {' '.join(settings.app_origin_list)}; frame-ancestors 'none'; base-uri 'none'"
    )
    return {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        # Not `no-referrer`: under that policy browsers send `Origin: null` on the service's own form posts,
        # which the same-origin check above would refuse.
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cache-Control": "no-store",
    }


class BodyLimit:
    """Refuses request bodies over MAX_BODY_BYTES (declared or streamed) with 413: every form here is a few fields."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_bytes):
            await _too_large(send)
            return
        seen = 0

        async def limited() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise _TooLargeError
            return message

        try:
            await self.app(scope, limited, send)
        except _TooLargeError:
            await _too_large(send)


class _TooLargeError(Exception):
    pass


async def _too_large(send: Send) -> None:
    await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"Request too large."})
