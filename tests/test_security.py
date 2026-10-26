"""Origin allowlist in the same-origin check, CSP and CORS headers (spec SI-3, SI-4)."""

from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from identity.config import Settings
from identity.redirects import post_signout_target
from identity.web.security import cors_headers, same_origin, security_headers

LMS, IDE = "https://test.vetfab.ai", "https://demo.vetfab.ai"


def settings(environment: str = "staging", **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": environment,
        "database_url": "postgresql://x@db/lms",
        "issuer": f"{LMS}/auth",
        "audience": "vetfab",
        "app_origins": f"{LMS},{IDE}",
        "keys_dir": Path("/keys"),
        **overrides,
    }
    return Settings(_env_file=None, **values)  # pyright: ignore[reportCallIssue]


def request(headers: dict[str, str]) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "POST", "path": "/auth/logout", "headers": raw, "query_string": b""})


@pytest.mark.parametrize("environment", ["development", "staging"])
def test_a_sibling_product_origin_may_post_same_site_where_allowed(environment: str) -> None:
    headers = {"origin": IDE, "sec-fetch-site": "same-site"}
    assert same_origin(request(headers), settings(environment), allow_siblings=True)


def test_a_sibling_product_origin_may_not_post_sign_in_forms() -> None:
    assert not same_origin(request({"origin": IDE, "sec-fetch-site": "same-site"}), settings())
    assert not same_origin(request({"origin": IDE}), settings())


def test_the_identity_origin_itself_must_be_same_origin_when_deployed() -> None:
    assert not same_origin(request({"origin": LMS, "sec-fetch-site": "same-site"}), settings())
    assert same_origin(request({"origin": LMS, "sec-fetch-site": "same-origin"}), settings())


@pytest.mark.parametrize(
    "headers",
    [
        {"origin": IDE, "sec-fetch-site": "cross-site"},
        {"origin": "https://evil.example", "sec-fetch-site": "same-site"},
        {"origin": "null"},
        {"sec-fetch-site": "same-origin"},
    ],
)
def test_other_posts_are_refused(headers: dict[str, str]) -> None:
    assert not same_origin(request(headers), settings())


def test_cors_headers_only_for_allowlisted_origin() -> None:
    assert cors_headers(request({"origin": IDE}), settings()) == {
        "Access-Control-Allow-Origin": IDE,
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    }
    assert cors_headers(request({"origin": "https://evil.example"}), settings()) is None
    assert cors_headers(request({"origin": f"{IDE}/x"}), settings()) is None
    assert cors_headers(request({}), settings()) is None


def test_csp_lists_every_origin() -> None:
    assert f"form-action 'self' {LMS} {IDE};" in security_headers(settings())["Content-Security-Policy"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/signout?done=1", "/signout?done=1"),
        (f"{IDE}/signed-out", f"{IDE}/signed-out"),
        (f"{IDE}", f"{IDE}/"),
        (f"{LMS}/x", "/x"),
        ("https://evil.example/x", "/"),
        (f"{IDE}@evil.example/x", "/"),
        ("//evil.example/x", "/"),
        (None, "/"),
    ],
)
def test_post_signout_target(value: str | None, expected: str) -> None:
    assert post_signout_target(value, settings()) == expected


def test_an_unparseable_origin_is_refused_even_with_an_unparseable_issuer() -> None:
    s = settings("development", issuer="not-a-url", app_origins="http://localhost:3100")
    assert not same_origin(request({"origin": "garbage"}), s)


def test_on_its_own_host_identity_accepts_the_lms_sign_out_but_not_its_sign_in() -> None:
    """Identity at auth.vetfab.ai: the LMS (first app origin) is then a sibling like the IDE. Its sign-out form
    arrives same-site and must be accepted; a sign-in form posted from it must still be refused (login CSRF)."""
    s = settings("staging", issuer="https://auth.vetfab.ai/auth")
    lms_post = request({"origin": LMS, "sec-fetch-site": "same-site"})
    assert same_origin(lms_post, s, allow_siblings=True)
    assert not same_origin(lms_post, s)
    own = request({"origin": "https://auth.vetfab.ai", "sec-fetch-site": "same-origin"})
    assert same_origin(own, s)
    assert not same_origin(request({"origin": "https://auth.vetfab.ai", "sec-fetch-site": "same-site"}), s)


def test_on_its_own_host_sign_out_returns_to_the_lms_not_to_itself() -> None:
    s = settings("staging", issuer="https://auth.vetfab.ai/auth")
    assert post_signout_target("/signout?done=1", s) == f"{LMS}/signout?done=1"
    assert post_signout_target(None, s) == f"{LMS}/"
    assert post_signout_target(f"{IDE}/x", s) == f"{IDE}/x"
