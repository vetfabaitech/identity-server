"""A fake identity service for the adapter tests: signing keys and a JWKS endpoint over a mock transport, no network."""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

AUTH_URL = "http://localhost:8200"
ISSUER = f"{AUTH_URL}/auth"


@dataclass
class Signer:
    key: rsa.RSAPrivateKey
    kid: str

    @classmethod
    def new(cls) -> "Signer":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return cls(key, hashlib.sha256(der).hexdigest()[:16])

    def jwk(self) -> dict[str, Any]:
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return jwk

    def token(
        self,
        *,
        sub: str | None = None,
        iss: str = ISSUER,
        aud: str = "vetfab",
        lifetime: int = 900,
        issued_at: int | None = None,
        typ: str = "at+jwt",
        kid: str | None = None,
        no_kid: bool = False,
        drop: tuple[str, ...] = (),
    ) -> str:
        now = int(time.time()) if issued_at is None else issued_at
        claims: dict[str, Any] = {
            "sub": sub or str(uuid.uuid4()),
            "iss": iss,
            "aud": aud,
            "iat": now,
            "exp": now + lifetime,
            "jti": uuid.uuid4().hex,
        }
        for name in drop:
            claims.pop(name)
        headers: dict[str, Any] = {"typ": typ}
        if not no_kid:
            headers["kid"] = kid or self.kid
        return jwt.encode(claims, self.key, algorithm="RS256", headers=headers)


@dataclass
class FakeIdentity:
    """The identity service's JWKS endpoint: change `signers` to rotate, set `down` to simulate an outage."""

    signers: list[Signer] = field(default_factory=lambda: [Signer.new()])
    down: bool = False
    fetches: int = 0

    @property
    def signer(self) -> Signer:
        return self.signers[-1]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.fetches += 1
        if self.down:
            return httpx.Response(503)
        return httpx.Response(200, json={"keys": [s.jwk() for s in self.signers]})


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
