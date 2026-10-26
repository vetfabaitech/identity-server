"""Where the browser may go after sign-in, and the sign-in `state` nonce.

A target is an allowlisted origin plus a path (spec SI-4). A path-only `redirect` lands on the default origin (the
first of IDENTITY_APP_ORIGINS, the LMS web app), exactly as before; an absolute URL is accepted only when it starts
with one of the allowlisted origins character for character, followed by nothing or a path, so userinfo, other ports
and look-alike hosts never match.

A port of apps/web/src/lib/auth/redirect.ts (`postSignInTarget`): a same-origin path, pre-screened for control
characters, whitespace, backslashes and scheme-relative forms, with dot segments (also percent-encoded ones) resolved
before the checks, the way the browser's URL parser would. The web app validates again after the hand-off; this is the
identity service's own line of defence, so it never echoes an attacker's URL into a Location header.
"""

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from identity.config import Settings


def origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


MAX_REDIRECT_LENGTH = 2048
MAX_STATE_LENGTH = 128

_FORBIDDEN = re.compile(r"[\u0000- \u007f-\u009f  \\]")
# The web app's nonce is base64url; unreserved URL characters only, so it needs no escaping anywhere.
_STATE = re.compile(rf"^[A-Za-z0-9._~-]{{1,{MAX_STATE_LENGTH}}}$")
_SINGLE_DOT = {".", "%2e"}
_DOUBLE_DOT = {"..", ".%2e", "%2e.", "%2e%2e"}
# Paths of the web app's own sign-in and sign-out flow (apps/web/src/lib/auth/routes.ts NON_DESTINATIONS).
_AUTH_FLOW = ("/signin", "/handoff", "/signout", "/bff")


def _normalise(value: str | None) -> tuple[str, str] | None:
    """Returns (pathname, href) or None when the value is not a safe same-origin path."""
    if not isinstance(value, str) or not value or len(value) > MAX_REDIRECT_LENGTH:
        return None
    if _FORBIDDEN.search(value) or not value.startswith("/") or value.startswith("//"):
        return None
    cut = min((i for i in (value.find("?"), value.find("#")) if i >= 0), default=len(value))
    raw_path, suffix = value[:cut], value[cut:]
    segments = raw_path.split("/")[1:]
    out: list[str] = []
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        lowered = segment.lower()
        if lowered in _SINGLE_DOT:
            if last:
                out.append("")
            continue
        if lowered in _DOUBLE_DOT:
            if out:
                out.pop()
            if last:
                out.append("")
            continue
        out.append(segment)
    pathname = "/" + "/".join(out)
    href = pathname + suffix
    if href.startswith("//") or len(href) > MAX_REDIRECT_LENGTH:
        return None
    return pathname, href


def _under(pathname: str, prefix: str) -> bool:
    return pathname == prefix or pathname.startswith(prefix + "/")


@dataclass(frozen=True, slots=True)
class Target:
    """Where a hand-off lands: an allowlisted origin and a normalised same-origin path on it."""

    origin: str
    path: str
    default_origin: str

    @property
    def param(self) -> str:
        """The value to carry in forms and links: the bare path on the default origin, else origin + path."""
        return self.path if self.origin == self.default_origin else f"{self.origin}{self.path}"

    @property
    def handoff_base(self) -> str:
        return f"{self.origin}/handoff"


def _signin_path(value: str | None) -> str:
    normalised = _normalise(value)
    if normalised is None or any(_under(normalised[0], p) for p in _AUTH_FLOW):
        return "/"
    return normalised[1]


def post_signin_target(value: str | None, settings: Settings) -> Target:
    default = settings.app_origin
    if isinstance(value, str) and len(value) <= MAX_REDIRECT_LENGTH:
        for origin in settings.app_origin_list:
            rest = value[len(origin) :] if value.startswith(origin) else None
            if rest is not None and (rest == "" or rest.startswith("/")):
                return Target(origin, _signin_path(rest or "/"), default)
    return Target(default, _signin_path(value), default)


def safe_path(value: str | None, fallback: str = "/") -> str:
    """A same-origin path (auth-flow paths allowed), for redirects after sign-out."""
    normalised = _normalise(value)
    return normalised[1] if normalised else fallback


def valid_state(value: str | None) -> str | None:
    """The web app's one-time sign-in nonce, passed through untouched when it is plausible."""
    return value if isinstance(value, str) and _STATE.match(value) else None


def post_signout_target(value: str | None, settings: Settings) -> str:
    """Where sign-out returns: a safe path on the default origin, or an absolute URL on another allowlisted origin.

    Auth-flow paths are allowed here (the LMS returns to /signout?done=1). A bare path stays relative only while the
    default origin is this service's own host (the test box layout); with the service on its own host it is made
    absolute on the default origin, or the browser would resolve it against the identity host.
    """
    default = settings.app_origin
    relative_ok = default == origin_of(settings.issuer)

    def on(origin: str, path: str) -> str:
        return path if origin == default and relative_ok else f"{origin}{path}"

    if isinstance(value, str) and len(value) <= MAX_REDIRECT_LENGTH:
        for origin in settings.app_origin_list:
            rest = value[len(origin) :] if value.startswith(origin) else None
            if rest is not None and (rest == "" or rest.startswith("/")):
                return on(origin, safe_path(rest or "/"))
    return on(default, safe_path(value))
