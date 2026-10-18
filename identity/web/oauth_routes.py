"""GitHub and Google sign-in under /auth/oauth (spec SI-5, §4).

`start` remembers where to hand off and a one-time nonce in a cookie on Path=/auth, then sends the browser to the
provider with the nonce as `state`. The provider returns the browser to `callback` with a top-level GET (so the
SameSite=Lax cookie is sent); the callback refuses anything whose `state` is not that cookie's nonce, which stops a
forged callback from signing a victim into an attacker's account. Only then is the code exchanged.
"""

import hmac
import logging
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from identity import sessions, store
from identity.oauth import PROVIDERS, OAuthError, Provider
from identity.oauth.resolve import resolve_user
from identity.redirects import Target, post_signin_target, valid_state
from identity.web import cookies
from identity.web.routes import INACTIVE, _client, _handoff, _login_page, _pool, _settings

router = APIRouter(prefix="/auth/oauth")
log = logging.getLogger("identity.oauth")

OAUTH_STATE_MESSAGE = "This sign-in link has expired. Please try again."
OAUTH_DENIED = "Sign-in with {provider} was cancelled."
OAUTH_FAILED = "Unable to sign in with {provider}. Please try again."
NO_VERIFIED_EMAIL = "Your {provider} account has no verified email address. Verify one with {provider}, then try again."


def _provider(request: Request, name: str) -> Provider | None:
    provider = PROVIDERS.get(name)
    return provider if provider is not None and provider.configured(_settings(request)) else None


@router.get("/{name}/start")
async def oauth_start(request: Request, name: str, redirect: str | None = None, state: str | None = None) -> Response:
    provider = _provider(request, name)
    if provider is None:
        return Response(status_code=404)
    settings = _settings(request)
    target = post_signin_target(redirect, settings)
    nonce = secrets.token_urlsafe(32)
    response = RedirectResponse(provider.authorize_url(settings, nonce), status_code=302)
    remembered = cookies.OAuthState(nonce=nonce, redirect=target.param, state=valid_state(state))
    cookies.set_cookie(
        response, cookies.OAUTH_STATE, cookies.oauth_state_value(remembered), settings, cookies.OAUTH_STATE_SECONDS
    )
    return response


async def _audit_failure(request: Request, provider: str, reason: str, ip: str, agent: str | None) -> None:
    async with _pool(request).connection() as conn:
        await store.audit(
            conn, "signin_failed", ip=ip, user_agent=agent, metadata={"reason": reason, "provider": provider}
        )


def _fail(request: Request, target: Target, state: str | None, status: int, message: str) -> Response:
    page = _login_page(request, target, state, status, message)
    cookies.clear_cookie(page, cookies.OAUTH_STATE, _settings(request))
    return page


@router.get("/{name}/callback")
async def oauth_callback(
    request: Request, name: str, code: str | None = None, state: str | None = None, error: str | None = None
) -> Response:
    provider = _provider(request, name)
    if provider is None:
        return Response(status_code=404)
    settings = _settings(request)
    remembered = cookies.read_oauth_state(request.cookies.get(cookies.cookie_name(cookies.OAUTH_STATE, settings)))
    target = post_signin_target(remembered.redirect if remembered else None, settings)
    nonce = valid_state(remembered.state) if remembered else None
    if remembered is None or not state or not hmac.compare_digest(state.encode(), remembered.nonce.encode()):
        log.warning(
            "oauth %s callback refused: state %s", provider.name, "cookie missing" if remembered is None else "mismatch"
        )
        return _fail(request, target, nonce, 400, OAUTH_STATE_MESSAGE)
    if error or not code:
        return _fail(request, target, nonce, 400, OAUTH_DENIED.format(provider=provider.label))
    ip, agent = _client(request)
    try:
        profile = await provider.fetch_profile(settings, code)
    except OAuthError as exc:
        log.warning("oauth %s sign-in failed: %s", provider.name, exc)
        await _audit_failure(request, provider.name, "oauth_provider", ip, agent)
        return _fail(request, target, nonce, 502, OAUTH_FAILED.format(provider=provider.label))

    async with _pool(request).connection() as conn:
        try:
            resolved = await resolve_user(conn, profile, settings)
        except OAuthError as exc:
            log.warning("oauth %s sign-in refused: %s", provider.name, exc)
            await store.audit(
                conn, "signin_failed", ip=ip, user_agent=agent,
                metadata={"reason": exc.reason, "provider": provider.name},
            )  # fmt: skip
            return _fail(request, target, nonce, 400, NO_VERIFIED_EMAIL.format(provider=provider.label))
        user = resolved.user
        if not user.active:
            await store.audit(
                conn, "signin_failed", user_id=user.id, ip=ip, user_agent=agent,
                metadata={"reason": user.status, "provider": provider.name},
            )  # fmt: skip
            return _fail(request, target, nonce, 403, INACTIVE)
        await store.touch_login(conn, user.id)
        raw = await sessions.issue(conn, user, settings, agent)
        await store.audit(
            conn, "oauth_signin", user_id=user.id, ip=ip, user_agent=agent,
            metadata={"provider": provider.name, "outcome": resolved.outcome},
        )  # fmt: skip
    response = _handoff(request, user, target, nonce)
    cookies.set_refresh(response, raw, settings)
    cookies.clear_cookie(response, cookies.OAUTH_STATE, settings)
    return response
