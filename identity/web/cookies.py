"""The identity service's two cookies, both scoped to `Path=/auth` so the web app never receives them.

* refresh: the raw refresh token (sessions.py), HttpOnly, SameSite=Lax, Secure with the `__Secure-` prefix over https.
* test pass: proof that this browser entered the test-accounts passphrase, `<expiry>.<hmac>` keyed by a hash of the
  passphrase, so changing the passphrase invalidates every pass at once. Only meaningful in test-accounts mode.
* OAuth state: the provider round trip's one-time nonce plus where to hand off afterwards (spec SI-5), base64url
  JSON, 10 minutes. The nonce is the CSRF defence for the callback; the stored target is re-validated on return.
"""

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from starlette.responses import Response

from identity.config import Settings

PATH = "/auth"
REFRESH = "vf_refresh"
TEST_PASS = "vf_test_pass"  # noqa: S105  # a cookie name, not a secret
TEST_PASS_SECONDS = 12 * 3600
OAUTH_STATE = "vf_oauth_state"
OAUTH_STATE_SECONDS = 600
_MAX_OAUTH_STATE = 3000


def cookie_name(base: str, settings: Settings) -> str:
    return f"__Secure-{base}" if settings.secure_cookies else base


def set_cookie(response: Response, base: str, value: str, settings: Settings, max_age: int) -> None:
    response.set_cookie(
        cookie_name(base, settings),
        value,
        max_age=max_age,
        path=PATH,
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )


def clear_cookie(response: Response, base: str, settings: Settings) -> None:
    response.delete_cookie(
        cookie_name(base, settings), path=PATH, secure=settings.secure_cookies, httponly=True, samesite="lax"
    )


def set_refresh(response: Response, raw: str, settings: Settings) -> None:
    set_cookie(response, REFRESH, raw, settings, settings.refresh_token_days * 86_400)


def _pass_signature(settings: Settings, expires: int) -> str:
    secret = settings.test_accounts_passphrase.get_secret_value() if settings.test_accounts_passphrase else ""
    key = hashlib.sha256(f"vf-test-pass-key:{secret}".encode()).digest()
    return hmac.new(key, f"vf-test-pass:{expires}".encode(), hashlib.sha256).hexdigest()


def test_pass_value(settings: Settings, now: int | None = None) -> str:
    expires = (int(time.time()) if now is None else now) + TEST_PASS_SECONDS
    return f"{expires}.{_pass_signature(settings, expires)}"


def test_pass_valid(settings: Settings, value: str | None, now: int | None = None) -> bool:
    if not settings.test_accounts or not value or "." not in value:
        return False
    expires_text, signature = value.split(".", 1)
    if not expires_text.isdigit() or int(expires_text) <= (int(time.time()) if now is None else now):
        return False
    return hmac.compare_digest(signature, _pass_signature(settings, int(expires_text)))


@dataclass(frozen=True, slots=True)
class OAuthState:
    nonce: str
    redirect: str
    state: str | None


def oauth_state_value(value: OAuthState) -> str:
    raw = json.dumps({"n": value.nonce, "r": value.redirect, "s": value.state or ""}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode("ascii")


def read_oauth_state(value: str | None) -> OAuthState | None:
    if not value or len(value) > _MAX_OAUTH_STATE:
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
    except (binascii.Error, ValueError):
        return None
    if not isinstance(data, dict) or not all(isinstance(data.get(k), str) for k in ("n", "r", "s")) or not data["n"]:
        return None
    return OAuthState(nonce=data["n"], redirect=data["r"], state=data["s"] or None)
