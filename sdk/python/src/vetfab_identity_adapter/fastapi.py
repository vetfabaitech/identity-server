"""FastAPI integration: dependencies that authenticate a request and let the application authorise it.

```python
adapter = IdentityAdapter.from_env()
guard = IdentityGuard(adapter, load_user)          # load_user(identity) -> your user object, or None

@app.get("/me")
async def me(user: User = Depends(guard.user)): ...

@app.post("/admin/x")
async def admin_only(user: User = Depends(guard.require(lambda u: u.role == "admin"))): ...
```

Authentication (who is this) is the adapter's; authorisation (what may they do) stays in the application: a valid
identity grants nothing until `load_user` finds an account and a `require` check passes. Failures are 401 (no or bad
token), 403 (valid identity, not allowed) and 503 (identity keys unreachable); bodies carry a short `code`, never
the token, claims or exception text.
"""

import logging
from collections.abc import Awaitable, Callable
from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from vetfab_identity_adapter.adapter import IdentityAdapter, VerifiedIdentity, bearer_token
from vetfab_identity_adapter.handoff import (
    HandoffRedeemer,
    HandoffRejectedError,
    HandoffUnavailableError,
    SessionCookie,
)
from vetfab_identity_adapter.verifier import InvalidTokenError, SigningKeysUnavailableError

log = logging.getLogger("vetfab_identity_adapter")

type UserLoader[U] = Callable[[VerifiedIdentity], Awaitable[U | None]]


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_FORM_BYTES = 4096
_PAGE = (
    "<!doctype html><html lang=en><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'><title>{title}</title>"
    "<body style='font:16px system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem'>"
    "<h1>{title}</h1><p>{message}</p><p><a href='/'>Continue</a></p>"
)


def _unauthenticated(code: str, error: str | None = None) -> HTTPException:
    challenge = "Bearer" if error is None else f'Bearer error="{error}"'
    return HTTPException(401, detail={"code": code}, headers={"WWW-Authenticate": challenge})


class IdentityGuard[U]:
    """Holds the dependencies `identity`, `user` and `require(...)` for one application.

    `load_user` maps a verified identity to the application's own user (reading its status and roles from its own
    store). Return None for an id the application has never seen: the guard answers 403 `account_not_provisioned`,
    unless `load_user` provisions the account itself (CONTRACT.md: a product must handle a user it has never seen).
    """

    def __init__(
        self,
        adapter: IdentityAdapter,
        load_user: UserLoader[U],
        *,
        sessions: SessionCookie | None = None,
        app_origin: str | None = None,
    ) -> None:
        """`sessions` and `app_origin` (this service's own origin) additionally accept the cookie session an SSO
        hand-off starts. A request with an `Authorization` header is judged by that header alone; one without it, by
        the cookie. Cookie requests that change state must come from this service's own origin (CSRF)."""
        if (sessions is None) != (app_origin is None):
            raise ValueError("IdentityGuard needs sessions and app_origin together.")
        self.adapter = adapter
        self._load_user = load_user
        self._sessions = sessions
        self._app_origin = app_origin
        self.identity: Callable[..., Awaitable[VerifiedIdentity]] = self._identity
        self.user: Callable[..., Awaitable[U]] = self._user

    async def _identity(self, request: Request) -> VerifiedIdentity:
        """Dependency: the verified identity from the bearer token (or session cookie). Touches no database."""
        header = request.headers.get("authorization")
        if header is None and self._sessions is not None:
            return self._from_cookie(request, self._sessions)
        token = bearer_token(header)
        if token is None:
            raise _unauthenticated("not_authenticated")
        try:
            return await self.adapter.verify(token)
        except SigningKeysUnavailableError:
            log.error("identity signing keys unavailable; refusing requests until they can be fetched")
            raise HTTPException(503, detail={"code": "identity_unavailable"}, headers={"Retry-After": "5"}) from None
        except InvalidTokenError as exc:
            # The exception names the failed check (expired, wrong audience, ...), never the token.
            log.info("rejected bearer token: %s", exc)
            raise _unauthenticated("invalid_token", "invalid_token") from None

    def _from_cookie(self, request: Request, sessions: SessionCookie) -> VerifiedIdentity:
        identity = sessions.read(request.cookies.get(sessions.name))
        if identity is None:
            raise _unauthenticated("not_authenticated")
        if request.method not in SAFE_METHODS and request.headers.get("origin") != self._app_origin:
            # A cookie is sent by the browser whoever asked, so a state-changing request must prove it came from here.
            raise HTTPException(403, detail={"code": "csrf"})
        return identity

    async def _user(self, request: Request) -> U:
        """Dependency: the application's user for the verified identity."""
        identity = await self._identity(request)
        user = await self._load_user(identity)
        if user is None:
            raise HTTPException(403, detail={"code": "account_not_provisioned"})
        return user

    def require(self, check: Callable[[U], bool], code: str = "forbidden") -> Callable[..., Awaitable[U]]:
        """Dependency factory: the application's user, provided `check(user)` holds, else 403 with `code`."""

        async def dependency(request: Request) -> U:
            user = await self._user(request)
            if not check(user):
                raise HTTPException(403, detail={"code": code})
            return user

        return dependency


def _page(status: int, title: str, message: str) -> HTMLResponse:
    return HTMLResponse(
        _PAGE.format(title=title, message=message),
        status_code=status,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


def handoff_router[U](
    redeemer: HandoffRedeemer,
    sessions: SessionCookie,
    load_user: UserLoader[U],
    *,
    app_origin: str,
    callback_path: str = "/handoff/redeem",
    prefix: str = "/handoff",
) -> APIRouter:
    """The destination routes of an SSO hand-off.

    `POST <callback_path>` receives the ticket, `GET <prefix>/session` says who is signed in on this service (for the
    page) and `POST <prefix>/logout` ends this service's own session.

    Mount it where the identity registry lists this service's `callback_path`. The ticket arrives in a form body, never
    a URL; the answer is a redirect that starts this service's session, so the ticket never reaches page scripts,
    history or a Referer header. `load_user` is the application's own authorisation (None: not provisioned here).
    """
    router = APIRouter()

    @router.post(callback_path, include_in_schema=False)
    async def redeem(request: Request) -> Response:
        if not request.headers.get("content-type", "").lower().startswith("application/x-www-form-urlencoded"):
            return _page(415, "Sign-in not completed", "The request was not a sign-in hand-off.")
        raw = await request.body()
        if len(raw) > MAX_FORM_BYTES:
            return _page(413, "Sign-in not completed", "The request was too large.")
        tickets = parse_qs(raw.decode("utf-8", "replace")).get("ticket", [])
        if len(tickets) != 1:
            return _page(400, "Sign-in not completed", "The sign-in link is not valid. Please try again.")
        try:
            redemption = await redeemer.redeem(tickets[0])
        except HandoffRejectedError:
            return _page(
                400, "Sign-in not completed", "The sign-in link is not valid or has expired. Please try again."
            )
        except HandoffUnavailableError:
            return _page(503, "Sign-in unavailable", "The sign-in service is not reachable. Please try again shortly.")
        # The ticket was issued to a page on the source service's origin; a page anywhere else posting it is an attack.
        if request.headers.get("origin") != redemption.source_origin:
            log.warning("hand-off ticket posted from outside its source service %s", redemption.source_service)
            return _page(403, "Sign-in not completed", "The sign-in did not come from a Vetfab service.")
        if await load_user(VerifiedIdentity(user_id=redemption.user_id, expires_at=0)) is None:
            return _page(403, "No access", "Your account does not have access to this service.")
        response = RedirectResponse(redemption.return_path, status_code=303)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.set_cookie(sessions.name, sessions.issue(redemption.user_id), **sessions.cookie_attributes())  # pyright: ignore[reportArgumentType]
        return response

    @router.get(f"{prefix}/session", include_in_schema=False)
    async def session(request: Request) -> Response:
        identity = sessions.read(request.cookies.get(sessions.name))
        if identity is None:
            return JSONResponse({"error": "no_session"}, status_code=401, headers={"Cache-Control": "no-store"})
        body = {"user_id": str(identity.user_id), "expires_at": identity.expires_at}
        return JSONResponse(body, headers={"Cache-Control": "no-store"})

    @router.post(f"{prefix}/logout", include_in_schema=False)
    async def logout(request: Request) -> Response:
        """Ends THIS service's session only: the identity service's session, and so the others', is untouched."""
        if request.headers.get("origin") != app_origin:
            return JSONResponse({"error": "csrf"}, status_code=403)
        response = Response(status_code=204)
        attributes = sessions.cookie_attributes()
        response.delete_cookie(
            sessions.name, path="/", secure=attributes["secure"] is True, httponly=True, samesite="lax"
        )
        return response

    return router
