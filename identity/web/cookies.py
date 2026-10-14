"""The identity service's two cookies, both scoped to `Path=/auth` so the web app never receives them.

* refresh: the raw refresh token (sessions.py), HttpOnly, SameSite=Lax, Secure with the `__Secure-` prefix over https.
* test pass: proof that this browser entered the test-accounts passphrase, `<expiry>.<hmac>` keyed by a hash of the
  passphrase, so changing the passphrase invalidates every pass at once. Only meaningful in test-accounts mode.
"""

import hashlib
import hmac
import time

from starlette.responses import Response

from identity.config import Settings

PATH = "/auth"
REFRESH = "vf_refresh"
TEST_PASS = "vf_test_pass"  # noqa: S105  # a cookie name, not a secret
TEST_PASS_SECONDS = 12 * 3600


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
