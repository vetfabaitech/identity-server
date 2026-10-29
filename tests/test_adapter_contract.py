"""The backend adapter accepts what this service really mints, and agrees with the LMS verifier on everything else.

No database: tokens come from `identity.tokens.mint_access_token` with a throwaway key ring, and the JWKS is served
from `KeyRing.jwks()` over a mock transport, so this checks the real signing code against the adapter.
"""

import time
import uuid
from pathlib import Path

import httpx
import pytest

from identity.config import Settings
from identity.keys import KeyRing, generate_key
from identity.tokens import mint_access_token
from tests.contract.verifier import (
    InvalidTokenError as LmsInvalid,
)
from tests.contract.verifier import (
    JwksKeyStore,
    JwksSource,
    TokenPolicy,
    TokenVerifier,
)
from vetfab_identity_adapter import AdapterConfig, IdentityAdapter, InvalidTokenError

ISSUER = "https://auth.example.test/auth"


@pytest.fixture(scope="module")
def ring(tmp_path_factory: pytest.TempPathFactory) -> KeyRing:
    directory: Path = tmp_path_factory.mktemp("adapter-keys")
    generate_key(directory)
    return KeyRing.load(directory)


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "staging",
        "database_url": "postgresql://unused",
        "issuer": ISSUER,
        "audience": "vetfab",
        "app_origins": "https://lms.example.test",
        "keys_dir": Path("unused"),
        **overrides,
    }
    return Settings(_env_file=None, **values)  # pyright: ignore[reportCallIssue, reportArgumentType]


def transport(ring: KeyRing) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(200, json=ring.jwks()))


def adapter_for(ring: KeyRing, audience: str = "vetfab") -> IdentityAdapter:
    config = AdapterConfig.build(
        auth_url="https://auth.example.test", environment="production", issuer=ISSUER, audience=audience
    )
    return IdentityAdapter(config, http=httpx.AsyncClient(transport=transport(ring)))


def lms_for(ring: KeyRing, audience: str = "vetfab") -> TokenVerifier:
    http = httpx.AsyncClient(transport=transport(ring))
    keys = JwksKeyStore(JwksSource(url="https://auth.example.test/auth/.well-known/jwks.json"), http=http)
    return TokenVerifier(TokenPolicy(issuer=ISSUER, audience=audience), keys)


async def test_a_minted_token_verifies_and_carries_only_the_user_id(ring: KeyRing) -> None:
    user = uuid.uuid4()
    token = mint_access_token(ring, settings(), user)
    verified = await adapter_for(ring).verify(token)
    assert verified.user_id == user
    assert (await lms_for(ring).verify(token)).user_id == user


@pytest.mark.parametrize(
    ("label", "audience", "now"),
    [
        ("valid", "vetfab", None),
        ("expired", "vetfab", int(time.time()) - 3600),
        ("other-audience", "other-platform", None),
    ],
)
async def test_adapter_and_lms_verifier_agree(ring: KeyRing, label: str, audience: str, now: int | None) -> None:
    token = mint_access_token(ring, settings(audience=audience), uuid.uuid4(), now=now)
    ours = lms = True
    try:
        await adapter_for(ring).verify(token)
    except InvalidTokenError:
        ours = False
    try:
        await lms_for(ring).verify(token)
    except LmsInvalid:
        lms = False
    assert ours == lms == (label == "valid")


async def test_a_token_from_another_issuer_is_refused(ring: KeyRing) -> None:
    token = mint_access_token(ring, settings(issuer="https://evil.example.test/auth"), uuid.uuid4())
    with pytest.raises(InvalidTokenError):
        await adapter_for(ring).verify(token)
