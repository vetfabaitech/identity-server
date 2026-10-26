"""Browser routes under /auth (spec §3.1).

Sign-in ends with a 303 to `<app origin>/handoff#token=…&redirect=…&state=…`, the contract the LMS web app already
implements (apps/web/src/app/(auth)/handoff). The access token travels only in the fragment, which browsers never send
to a server or put in a Referer.
"""

import asyncio
import hmac
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from psycopg_pool import AsyncConnectionPool
from starlette.concurrency import run_in_threadpool

from identity import sessions, store
from identity.config import Settings
from identity.keys import KeyRing
from identity.oauth import PROVIDERS, configured_providers
from identity.passwords import MAX_PASSWORD_LENGTH, verify_password
from identity.redirects import Target, post_signin_target, post_signout_target, valid_state
from identity.sessions import Issued
from identity.store import User
from identity.tokens import mint_access_token
from identity.web import cookies
from identity.web.security import cors_headers, same_origin

router = APIRouter(prefix="/auth")

INCORRECT = "Email or password is incorrect."
INACTIVE = "This account is not active. Contact your Vetfab administrator."
BUSY = "Sign-in is busy right now. Wait a few seconds and try again."
RETRY_AFTER_SECONDS = 2
CROSS_SITE = "This request did not come from the Vetfab sign-in page. Open the sign-in page and try again."
WRONG_PASSPHRASE = "That passphrase is not right."  # noqa: S105  # a user-facing message
MAX_EMAIL_LENGTH = 320


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _pool(request: Request) -> AsyncConnectionPool:
    return request.app.state.pool


def _keys(request: Request) -> KeyRing:
    return request.app.state.keys


def _client(request: Request) -> tuple[str, str | None]:
    return (request.client.host if request.client else "unknown"), request.headers.get("user-agent")


def _too_many(settings: Settings) -> str:
    return f"Too many attempts. Try again in {max(1, settings.rate_limit_window_seconds // 60)} minutes."


def _picker_url(target: Target, state: str | None) -> str:
    query = {"redirect": target.param, **({"state": state} if state else {})}
    return f"/auth/test-accounts?{urlencode(query)}"


def render(request: Request, template: str, status: int = 200, **context: Any) -> HTMLResponse:
    templates: Jinja2Templates = request.app.state.templates
    settings = _settings(request)
    return templates.TemplateResponse(
        request, template, {"test_accounts": settings.test_accounts, **context}, status_code=status
    )


def _login_page(
    request: Request, target: Target, state: str | None, status: int = 200, message: str | None = None, email: str = ""
) -> HTMLResponse:
    query = urlencode({"redirect": target.param, **({"state": state} if state else {})})
    providers = [
        {"label": PROVIDERS[name].label, "href": f"/auth/oauth/{name}/start?{query}"}
        for name in configured_providers(_settings(request))
    ]
    return render(
        request,
        "login.html",
        status,
        title="Sign in",
        redirect=target.param,
        state=state or "",
        message=message,
        email=email,
        picker_url=_picker_url(target, state),
        providers=providers,
    )


def _refused(request: Request) -> HTMLResponse:
    return render(request, "message.html", 403, title="Sign-in refused", message=CROSS_SITE)


def _handoff(request: Request, user: User, target: Target, state: str | None) -> RedirectResponse:
    token = mint_access_token(_keys(request), _settings(request), user.id)
    fragment = urlencode({"token": token, "redirect": target.path, **({"state": state} if state else {})})
    return RedirectResponse(f"{target.handoff_base}#{fragment}", status_code=303)


async def _form(request: Request) -> dict[str, str]:
    form = await request.form()
    return {k: v for k, v in form.items() if isinstance(v, str)}


# --------------------------------------------------------------------------- sign-in


@router.get("/login")
async def login_page(request: Request, redirect: str | None = None, state: str | None = None) -> Response:
    settings = _settings(request)
    target, nonce = post_signin_target(redirect, settings), valid_state(state)
    raw = request.cookies.get(cookies.cookie_name(cookies.REFRESH, settings))
    if not raw:
        return _login_page(request, target, nonce)
    ip, agent = _client(request)
    async with _pool(request).connection() as conn:
        renewal = await sessions.renew(conn, raw, settings, agent)
        if isinstance(renewal, Issued):
            await store.audit(conn, "refresh", user_id=renewal.user.id, ip=ip, user_agent=agent)
    if isinstance(renewal, Issued):
        response = _handoff(request, renewal.user, target, nonce)
        if renewal.refresh_token:
            cookies.set_refresh(response, renewal.refresh_token, settings)
        return response
    page = _login_page(request, target, nonce, message=INACTIVE if renewal.reason == "inactive" else None)
    cookies.clear_cookie(page, cookies.REFRESH, settings)
    return page


@router.post("/login")
async def login(request: Request) -> Response:
    settings = _settings(request)
    if not same_origin(request, settings):
        return _refused(request)
    form = await _form(request)
    email = form.get("email", "")[:MAX_EMAIL_LENGTH].strip()
    password = form.get("password", "")
    target, nonce = post_signin_target(form.get("redirect"), settings), valid_state(form.get("state"))
    ip, agent = _client(request)
    account = f"email:{store.normalise_email(email)}"
    # Three counters (config.py): this person, this account from anywhere, this address across accounts.
    limits = {
        f"{account}|ip:{ip}": settings.rate_limit_attempts,
        account: settings.rate_limit_account_attempts,
        f"ip:{ip}": settings.rate_limit_address_attempts,
    }
    keys, window = list(limits), settings.rate_limit_window_seconds
    # The whole sign-in runs under a process-wide bound (perf design §10; load test 2026-10-26): each password check
    # takes 64 MiB, and a pooled connection held for its duration starved every other request. The bound is taken
    # before the first database access, so a burst of sign-ins never contends for the pool either: at most this many
    # sign-ins touch the database at once, and everyone else is told to try again shortly. Unknown emails still hash
    # (against a dummy) under the same bound, so timing does not reveal which emails exist.
    slots: asyncio.Semaphore = request.app.state.verify_slots
    try:
        async with asyncio.timeout(settings.verify_queue_seconds):
            await slots.acquire()
    except TimeoutError:
        return busy_page(request, target, nonce, email)
    try:
        async with _pool(request).connection() as conn:
            if await store.rate_limited(conn, limits, window_seconds=window):
                return _login_page(request, target, nonce, 429, _too_many(settings), email)
            user = await store.find_user_by_email(conn, email) if email else None
        # The hash runs without a database connection.
        matched = await run_in_threadpool(verify_password, user.password_hash if user else None, password)
        async with _pool(request).connection() as conn:
            if user is None or not matched or len(password) > MAX_PASSWORD_LENGTH:
                await store.record_failure(conn, keys, window_seconds=window)
                await store.audit(
                    conn, "signin_failed", user_id=user.id if user else None, ip=ip, user_agent=agent,
                    metadata={"reason": "credentials"},
                )  # fmt: skip
                return _login_page(request, target, nonce, 401, INCORRECT, email)
            if not user.active:
                await store.audit(
                    conn, "signin_failed", user_id=user.id, ip=ip, user_agent=agent, metadata={"reason": user.status}
                )
                return _login_page(request, target, nonce, 403, INACTIVE, email)
            # A successful sign-in clears this person's and the account's counters, never the address's.
            await store.clear_failures(conn, keys[:2])
            await store.touch_login(conn, user.id)
            raw = await sessions.issue(conn, user, settings, agent)
            await store.audit(conn, "signin", user_id=user.id, ip=ip, user_agent=agent)
    finally:
        slots.release()
    response = _handoff(request, user, target, nonce)
    cookies.set_refresh(response, raw, settings)
    return response


def busy_page(request: Request, target: Target, state: str | None, email: str = "") -> HTMLResponse:
    """503 with Retry-After: the sign-in form again, with a message asking for a moment."""
    busy = _login_page(request, target, state, 503, BUSY, email)
    busy.headers["Retry-After"] = str(RETRY_AFTER_SECONDS)
    return busy


def busy_response(request: Request) -> Response:
    """Overload answer for any route when the database cannot hand out a connection in time (app.py): the same
    503 and Retry-After as a full sign-in queue, as JSON for the renewal endpoint and as a page everywhere else."""
    headers = {"Retry-After": str(RETRY_AFTER_SECONDS)}
    if request.url.path.startswith("/auth/session/"):
        cors = cors_headers(request, _settings(request)) or {}
        return JSONResponse({"error": "busy"}, status_code=503, headers={**headers, **cors})
    page = render(request, "message.html", 503, title="Sign-in is busy", message=BUSY)
    page.headers.update(headers)
    return page


@router.post("/logout")
async def logout(request: Request, redirect: str | None = None) -> Response:
    """Reached by the LMS web app's POST /bff/signout through a 307 (same-origin) or by a sibling product's form post
    (same-site, spec §4), so it is a POST, never a GET. `redirect` may be an absolute URL on an allowlisted origin."""
    settings = _settings(request)
    if not same_origin(request, settings, allow_siblings=True):
        return _refused(request)
    raw = request.cookies.get(cookies.cookie_name(cookies.REFRESH, settings))
    if raw:
        ip, agent = _client(request)
        async with _pool(request).connection() as conn:
            user_id = await sessions.revoke(conn, raw, "logout")
            if user_id:
                await store.audit(conn, "logout", user_id=user_id, ip=ip, user_agent=agent)
    response = RedirectResponse(post_signout_target(redirect, settings), status_code=303)
    cookies.clear_cookie(response, cookies.REFRESH, settings)
    return response


# --------------------------------------------------------------------------- XHR renewal (spec SI-4)


@router.options("/session/token")
async def session_token_preflight(request: Request) -> Response:
    cors = cors_headers(request, _settings(request))
    if cors is None:
        return Response(status_code=403)
    headers = {
        **cors,
        "Access-Control-Allow-Methods": "POST",
        "Access-Control-Allow-Headers": "content-type",
        "Access-Control-Max-Age": "600",
    }
    return Response(status_code=204, headers=headers)


@router.post("/session/token")
async def session_token(request: Request) -> Response:
    """A fresh access token from the refresh cookie, for a product page renewing in the background.

    Only allowlisted origins get an answer they can read, and any other origin is refused before the database is
    touched, so a foreign page cannot even rotate the cookie. The refresh token rotates exactly as on silent sign-in.
    """
    settings = _settings(request)
    cors = cors_headers(request, settings)
    if cors is None:
        return JSONResponse({"error": "origin"}, status_code=403)
    raw = request.cookies.get(cookies.cookie_name(cookies.REFRESH, settings))
    ip, agent = _client(request)
    async with _pool(request).connection() as conn:
        renewal = await sessions.renew(conn, raw, settings, agent)
        if isinstance(renewal, Issued):
            await store.audit(conn, "refresh", user_id=renewal.user.id, ip=ip, user_agent=agent)
    if not isinstance(renewal, Issued):
        rejected = JSONResponse({"error": renewal.reason}, status_code=401, headers=cors)
        cookies.clear_cookie(rejected, cookies.REFRESH, settings)
        return rejected
    token = mint_access_token(_keys(request), settings, renewal.user.id)
    response = JSONResponse({"access_token": token, "expires_in": settings.access_token_seconds}, headers=cors)
    if renewal.refresh_token:
        cookies.set_refresh(response, renewal.refresh_token, settings)
    return response


@router.get("/.well-known/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    return JSONResponse(_keys(request).jwks(), headers={"Cache-Control": "public, max-age=300"})


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# --------------------------------------------------------------------------- test accounts (spec TD-9)


def _picker_page(
    request: Request,
    target: Target,
    state: str | None,
    accounts: list[User] | None,
    status: int = 200,
    message: str | None = None,
) -> HTMLResponse:
    return render(
        request,
        "test_accounts.html",
        status,
        title="Test accounts",
        redirect=target.param,
        state=state or "",
        accounts=accounts,
        message=message,
        login_url=f"/auth/login?{urlencode({'redirect': target.param, **({'state': state} if state else {})})}",
    )


def _not_found() -> Response:
    return Response(status_code=404)


@router.get("/test-accounts")
async def test_accounts_page(request: Request, redirect: str | None = None, state: str | None = None) -> Response:
    settings = _settings(request)
    if not settings.test_accounts:
        return _not_found()
    target, nonce = post_signin_target(redirect, settings), valid_state(state)
    if not cookies.test_pass_valid(settings, request.cookies.get(cookies.cookie_name(cookies.TEST_PASS, settings))):
        return _picker_page(request, target, nonce, None)
    async with _pool(request).connection() as conn:
        accounts = await store.list_users_by_emails(conn, settings.test_account_emails)
    return _picker_page(request, target, nonce, accounts)


@router.post("/test-accounts")
async def unlock_test_accounts(request: Request) -> Response:
    settings = _settings(request)
    if not settings.test_accounts:
        return _not_found()
    if not same_origin(request, settings):
        return _refused(request)
    form = await _form(request)
    target, nonce = post_signin_target(form.get("redirect"), settings), valid_state(form.get("state"))
    ip, _ = _client(request)
    key = [f"pass:{ip}"]
    expected = settings.test_accounts_passphrase.get_secret_value() if settings.test_accounts_passphrase else ""
    async with _pool(request).connection() as conn:
        limit, window = settings.rate_limit_attempts, settings.rate_limit_window_seconds
        if await store.rate_limited(conn, {key[0]: limit}, window_seconds=window):
            return _picker_page(request, target, nonce, None, 429, _too_many(settings))
        if not hmac.compare_digest(form.get("passphrase", "").encode(), expected.encode()):
            await store.record_failure(conn, key, window_seconds=window)
            return _picker_page(request, target, nonce, None, 401, WRONG_PASSPHRASE)
        await store.clear_failures(conn, key)
    response = RedirectResponse(_picker_url(target, nonce), status_code=303)
    cookies.set_cookie(
        response, cookies.TEST_PASS, cookies.test_pass_value(settings), settings, cookies.TEST_PASS_SECONDS
    )
    return response


@router.post("/test-accounts/signin")
async def test_account_signin(request: Request) -> Response:
    settings = _settings(request)
    if not settings.test_accounts:
        return _not_found()
    if not same_origin(request, settings):
        return _refused(request)
    if not cookies.test_pass_valid(settings, request.cookies.get(cookies.cookie_name(cookies.TEST_PASS, settings))):
        return render(request, "message.html", 403, title="Test accounts", message="Enter the passphrase first.")
    form = await _form(request)
    target, nonce = post_signin_target(form.get("redirect"), settings), valid_state(form.get("state"))
    try:
        user_id = UUID(form.get("user_id", ""))
    except ValueError:
        return _not_found()
    ip, agent = _client(request)
    async with _pool(request).connection() as conn:
        user = await store.get_user(conn, user_id)
        if user is None or store.normalise_email(user.email) not in settings.test_account_emails:
            return _not_found()
        if not user.active:
            return render(request, "message.html", 403, title="Test accounts", message=INACTIVE)
        await store.touch_login(conn, user.id)
        raw = await sessions.issue(conn, user, settings, agent)
        await store.audit(conn, "test_signin", user_id=user.id, ip=ip, user_agent=agent)
    response = _handoff(request, user, target, nonce)
    cookies.set_refresh(response, raw, settings)
    return response
