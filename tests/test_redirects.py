"""Redirect and state validation, ported case for case from apps/web/src/lib/auth/auth-utils.test.ts.

The web app validates again after the hand-off; this is the identity service's own line of defence.
"""

from pathlib import Path

import pytest

from identity.config import Settings
from identity.redirects import post_signin_target, valid_state

DEFAULT, IDE = "https://test.vetfab.ai", "https://demo.vetfab.ai"
S = Settings(
    _env_file=None,  # pyright: ignore[reportCallIssue]
    environment="staging",
    database_url="postgresql://x@db/lms",
    issuer="https://test.vetfab.ai/auth",
    audience="vetfab",
    app_origins=f"{DEFAULT},{IDE}",
    keys_dir=Path("/keys"),
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/learn", "/learn"),
        ("/learn/labs?x=1", "/learn/labs?x=1"),
        (None, "/"),
        ("https://evil.example", "/"),
        ("//evil.example", "/"),
        ("/\\evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("learn", "/"),
        ("/learn\nSet-Cookie: x", "/"),
        ("/learn\t", "/"),
        ("/ learn", "/"),
        ("/learn ", "/"),
        ("///evil.example", "/"),
        ("/%2F%2Fevil.example", "/%2F%2Fevil.example"),
        ("/ide/?project=1", "/ide/?project=1"),
        ("", "/"),
        ("https:/evil.example", "/"),
        ("/" + "a" * 2048, "/"),
        ("/learn/./labs", "/learn/labs"),
        ("/learn/../teach", "/teach"),
        ("/learn/%2e%2e/teach", "/teach"),
        ("/learn/%2E%2E/%2e/teach?x=1#y", "/teach?x=1#y"),
        ("/../../../etc", "/etc"),
        ("/.//evil.example/x", "/"),
        ("/..//evil.example", "/"),
        ("/%2e//evil.example", "/"),
        ("/a/../..//evil.example", "/"),
        ("/learn/..", "/"),
        ("/learn/.", "/learn/"),
        # Auth-flow destinations would loop or sign the user out.
        ("/handoff", "/"),
        ("/learn/../handoff?x#token=abc", "/"),
        ("/learn/%2e%2e/handoff#token=abc", "/"),
        ("/./bff/signout", "/"),
        ("/learn/%2E%2E/bff/session", "/"),
        ("/signin?redirect=/learn", "/"),
        ("/signout", "/"),
        ("/handoffs", "/handoffs"),
        ("/learn/labs?tab=2#top", "/learn/labs?tab=2#top"),
    ],
)
def test_post_signin_target(value: str | None, expected: str) -> None:
    target = post_signin_target(value, S)
    assert (target.origin, target.path, target.param) == (DEFAULT, expected, expected)


def test_allowlisted_absolute_url_targets_that_origin() -> None:
    target = post_signin_target(f"{IDE}/projects/42?tab=files#top", S)
    assert (target.origin, target.path) == (IDE, "/projects/42?tab=files#top")
    assert target.param == f"{IDE}/projects/42?tab=files#top"
    assert target.handoff_base == f"{IDE}/handoff"


def test_absolute_url_on_the_default_origin_is_kept_as_a_path() -> None:
    target = post_signin_target(f"{DEFAULT}/learn", S)
    assert (target.origin, target.path, target.param) == (DEFAULT, "/learn", "/learn")


def test_origin_without_a_path_lands_on_its_root() -> None:
    assert post_signin_target(IDE, S).param == f"{IDE}/"


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.example/",
        "https://demo.vetfab.ai.evil.example/x",
        "https://demo.vetfab.ai@evil.example/x",
        "http://demo.vetfab.ai/x",
        "https://demo.vetfab.ai:8443/x",
        "HTTPS://evil.example/x",
        "javascript://demo.vetfab.ai/%0aalert(1)",
        " https://demo.vetfab.ai/x",
    ],
)
def test_foreign_origin_falls_back(value: str) -> None:
    target = post_signin_target(value, S)
    assert (target.origin, target.path, target.handoff_base) == (DEFAULT, "/", f"{DEFAULT}/handoff")


def test_dot_segments_and_auth_flow_paths_still_apply_on_other_origins() -> None:
    assert post_signin_target(f"{IDE}/a/%2e%2e/handoff", S).param == f"{IDE}/"
    assert post_signin_target(f"{IDE}/a/..//evil.example", S).param == f"{IDE}/"
    assert post_signin_target(f"{IDE}/a/../b", S).path == "/b"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Zm9vYmFy-_abc", "Zm9vYmFy-_abc"),
        ("a" * 128, "a" * 128),
        ("a" * 129, None),
        ("", None),
        (None, None),
        ("has space", None),
        ("tab\there", None),
        ("<script>", None),
    ],
)
def test_valid_state(value: str | None, expected: str | None) -> None:
    assert valid_state(value) == expected
