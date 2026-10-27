"""Token verification against a fake identity service: the checks CONTRACT.md requires of every product."""

import base64
import hashlib
import hmac
import json
import time
import uuid
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from fakes import Clock, FakeIdentity, Signer
from vetfab_identity_adapter import IdentityAdapter, InvalidTokenError, SigningKeysUnavailableError


async def test_valid_token_yields_the_subject(adapter: IdentityAdapter, identity: FakeIdentity) -> None:
    sub = str(uuid.uuid4())
    verified = await adapter.verify(identity.signer.token(sub=sub))
    assert str(verified.user_id) == sub


@pytest.mark.parametrize(
    "kwargs",
    [
        {"iss": "https://evil.example/auth"},
        {"aud": "another-platform"},
        {"lifetime": -120},  # expired beyond the 30 s leeway
        {"lifetime": 3600},  # longer than an access token may live
        {"issued_at": 4_000_000_000, "lifetime": 900},  # issued in the future
        {"typ": "JWT"},  # not an access token
        {"sub": "not-a-uuid"},
        {"drop": ("exp",)},
        {"drop": ("sub",)},
        {"drop": ("aud",)},
        {"drop": ("iss",)},
        {"drop": ("iat",)},
    ],
)
async def test_bad_tokens_are_rejected(
    adapter: IdentityAdapter, identity: FakeIdentity, kwargs: dict[str, Any]
) -> None:
    with pytest.raises(InvalidTokenError):
        await adapter.verify(identity.signer.token(**kwargs))


@pytest.mark.parametrize("token", ["", "x", "a.b.c", "a" * 9000, "eyJhbGciOiJub25lIn0.e30."])
async def test_malformed_tokens_are_rejected(adapter: IdentityAdapter, token: str) -> None:
    with pytest.raises(InvalidTokenError):
        await adapter.verify(token)


async def test_alg_none_is_rejected(adapter: IdentityAdapter) -> None:
    claims = {"sub": str(uuid.uuid4()), "iss": "x", "aud": "vetfab"}
    token = jwt.encode(claims, key=None, algorithm="none", headers={"typ": "at+jwt", "kid": "k"})  # pyright: ignore[reportArgumentType]
    with pytest.raises(InvalidTokenError, match="unsupported algorithm"):
        await adapter.verify(token)


async def test_public_key_cannot_be_used_as_an_hmac_secret(adapter: IdentityAdapter, identity: FakeIdentity) -> None:
    """Algorithm confusion: an HS256 token MACed with the published public key must not verify."""
    public_pem = identity.signer.key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def b64(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    now = int(time.time())
    header = {"alg": "HS256", "typ": "at+jwt", "kid": identity.signer.kid}
    claims = {"sub": str(uuid.uuid4()), "iss": adapter.config.issuer, "aud": "vetfab", "iat": now, "exp": now + 600}
    signing_input = b64(json.dumps(header).encode()) + b"." + b64(json.dumps(claims).encode())
    mac = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    forged = (signing_input + b"." + b64(mac)).decode()
    with pytest.raises(InvalidTokenError, match="unsupported algorithm"):
        await adapter.verify(forged)


async def test_token_signed_by_an_unpublished_key_is_rejected(adapter: IdentityAdapter) -> None:
    with pytest.raises(InvalidTokenError, match="unknown signing key"):
        await adapter.verify(Signer.new().token())


async def test_missing_kid_is_rejected(adapter: IdentityAdapter, identity: FakeIdentity) -> None:
    with pytest.raises(InvalidTokenError, match="missing key id"):
        await adapter.verify(identity.signer.token(no_kid=True))


async def test_rotated_key_is_picked_up_after_the_refetch_interval(
    adapter: IdentityAdapter, identity: FakeIdentity, clock: Clock
) -> None:
    old = identity.signer
    await adapter.verify(old.token())
    identity.signers.append(Signer.new())
    new_token = identity.signer.token()
    # An unknown kid refetches at most once per 30 seconds...
    with pytest.raises(InvalidTokenError):
        await adapter.verify(new_token)
    clock.advance(31)
    assert (await adapter.verify(new_token)).user_id
    # ...and the previous key keeps verifying while it is still published.
    assert (await adapter.verify(old.token())).user_id


async def test_removed_key_stops_verifying_after_a_refresh(
    adapter: IdentityAdapter, identity: FakeIdentity, clock: Clock
) -> None:
    old = identity.signer
    await adapter.verify(old.token())
    identity.signers = [Signer.new()]
    clock.advance(301)  # cache expired, keys refetched
    with pytest.raises(InvalidTokenError):
        await adapter.verify(old.token())


async def test_unknown_kids_cannot_amplify_into_identity_requests(
    adapter: IdentityAdapter, identity: FakeIdentity
) -> None:
    await adapter.verify(identity.signer.token())
    before = identity.fetches
    for _ in range(20):
        with pytest.raises(InvalidTokenError):
            await adapter.verify(Signer.new().token())
    assert identity.fetches - before <= 1


async def test_outage_with_no_cached_keys_is_distinct_from_a_bad_token(
    adapter: IdentityAdapter, identity: FakeIdentity
) -> None:
    identity.down = True
    with pytest.raises(SigningKeysUnavailableError):
        await adapter.verify(identity.signer.token())


async def test_cached_keys_survive_a_short_outage_but_not_an_hour(
    adapter: IdentityAdapter, identity: FakeIdentity, clock: Clock
) -> None:
    await adapter.verify(identity.signer.token())
    identity.down = True
    clock.advance(600)
    assert (await adapter.verify(identity.signer.token())).user_id  # stale but within an hour
    clock.advance(3000)
    with pytest.raises(SigningKeysUnavailableError):
        await adapter.verify(identity.signer.token())


async def test_adapters_do_not_share_keys(make_adapter: Callable[[], IdentityAdapter], identity: FakeIdentity) -> None:
    first, second = make_adapter(), make_adapter()
    await first.verify(identity.signer.token())
    assert identity.fetches == 1
    await second.verify(identity.signer.token())
    assert identity.fetches == 2
