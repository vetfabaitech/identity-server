"""Redirect and state validation, ported case for case from apps/web/src/lib/auth/auth-utils.test.ts.

The web app validates again after the hand-off; this is the identity service's own line of defence.
"""

import pytest

from identity.redirects import post_signin_target, valid_state


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
    assert post_signin_target(value) == expected


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
