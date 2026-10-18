"""Signing keys and access tokens: every minted token passes the API's own verifier (packages/authz)."""

import json
import os
import stat
import uuid
from pathlib import Path

import jwt
import pytest

from identity.config import Settings
from identity.keys import KeyRing, NoSigningKeyError, generate_key
from identity.tokens import mint_access_token
from vetfab_authz.tokens import JwksKeyStore, JwksSource, TokenPolicy, TokenVerifier

ISSUER = "https://test.vetfab.ai/auth"
AUDIENCE = "vetfab"


def settings_for(keys_dir: Path) -> Settings:
    return Settings(
        _env_file=None,  # pyright: ignore[reportCallIssue]
        environment="test",
        database_url="postgresql://unused",
        issuer=ISSUER,
        audience=AUDIENCE,
        app_origins="https://test.vetfab.ai",
        keys_dir=keys_dir,
    )


def api_verifier(ring: KeyRing, tmp_path: Path) -> TokenVerifier:
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps(ring.jwks()))
    return TokenVerifier(TokenPolicy(issuer=ISSUER, audience=AUDIENCE), JwksKeyStore(JwksSource(file=jwks_file)))


def test_generate_key_writes_a_private_pem_named_by_kid(tmp_path: Path) -> None:
    kid = generate_key(tmp_path)
    path = tmp_path / f"{kid}.pem"
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(kid) == 16
    assert KeyRing.load(tmp_path).signing_kid == kid


def test_the_newest_key_signs_and_every_key_is_published(tmp_path: Path) -> None:
    old = generate_key(tmp_path)
    new = generate_key(tmp_path)
    older = os.stat(tmp_path / f"{new}.pem").st_mtime_ns - 1_000_000_000
    os.utime(tmp_path / f"{old}.pem", ns=(older, older))
    ring = KeyRing.load(tmp_path)
    assert ring.signing_kid == new
    published = {k["kid"]: k for k in ring.jwks()["keys"]}
    assert set(published) == {old, new}
    assert all(k["kty"] == "RSA" and k["use"] == "sig" and k["alg"] == "RS256" for k in published.values())
    assert all("d" not in k for k in published.values()), "private material must never be published"


def test_an_empty_key_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(NoSigningKeyError):
        KeyRing.load(tmp_path)


async def test_minted_tokens_pass_the_api_verifier(tmp_path: Path) -> None:
    generate_key(tmp_path)
    ring = KeyRing.load(tmp_path)
    user_id = uuid.uuid4()
    token = mint_access_token(ring, settings_for(tmp_path), user_id)
    verified = await api_verifier(ring, tmp_path).verify(token)
    assert verified.user_id == user_id


def test_token_shape(tmp_path: Path) -> None:
    generate_key(tmp_path)
    ring = KeyRing.load(tmp_path)
    settings = settings_for(tmp_path)
    first = mint_access_token(ring, settings, uuid.uuid4(), now=1_000_000)
    second = mint_access_token(ring, settings, uuid.uuid4(), now=1_000_000)
    header = jwt.get_unverified_header(first)
    assert header == {"alg": "RS256", "kid": ring.signing_kid, "typ": "at+jwt"}
    claims = jwt.decode(first, options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 900
    assert claims["iss"] == ISSUER and claims["aud"] == AUDIENCE
    assert claims["jti"] != jwt.decode(second, options={"verify_signature": False})["jti"]
