"""RS256 signing keys.

`IDENTITY_KEYS_DIR` holds one PKCS#8 PEM per key, named `<kid>.pem`, where the kid is derived from the public key
(first 16 hex characters of the SHA-256 of its DER encoding) so a file can never claim another key's id. The most
recently written key signs; every key in the directory is published in the JWKS, so rotation is: write a new key,
restart, and delete the old file once the longest-lived token signed with it has expired (15 minutes).
"""

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

KEY_SIZE = 2048


class NoSigningKeyError(Exception):
    """The key directory holds no usable RSA private key."""


def key_id(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def generate_key(directory: Path) -> str:
    """Writes a new private key (mode 0600) and returns its kid."""
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    kid = key_id(key.public_key())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = directory / f"{kid}.pem"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    return kid


@dataclass(frozen=True, slots=True)
class KeyRing:
    signing_kid: str
    signing_key: rsa.RSAPrivateKey
    public_keys: dict[str, rsa.RSAPublicKey]

    @classmethod
    def load(cls, directory: Path) -> "KeyRing":
        loaded: list[tuple[int, str, rsa.RSAPrivateKey]] = []
        for path in directory.glob("*.pem") if directory.is_dir() else []:
            try:
                key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            except (ValueError, TypeError):
                continue
            if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < KEY_SIZE:
                continue
            loaded.append((path.stat().st_mtime_ns, key_id(key.public_key()), key))
        if not loaded:
            raise NoSigningKeyError(f"No RSA signing key in {directory}; run `identity-admin ensure-key`.")
        loaded.sort(key=lambda item: (item[0], item[1]))
        _, kid, key = loaded[-1]
        return cls(signing_kid=kid, signing_key=key, public_keys={k: priv.public_key() for _, k, priv in loaded})

    def jwks(self) -> dict[str, list[dict[str, Any]]]:
        keys = []
        for kid, public in sorted(self.public_keys.items()):
            jwk = json.loads(RSAAlgorithm.to_jwk(public))
            jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
            keys.append(jwk)
        return {"keys": keys}
