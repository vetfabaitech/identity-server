"""Access tokens in exactly the shape packages/authz verifies: RS256, `typ: at+jwt`, at most 15 minutes.

Only `sub` carries meaning. Status, roles and organisations are never put in the token: the LMS re-reads them from
the database on every request (plan §28, D-11 revised).
"""

import time
import uuid
from uuid import UUID

import jwt

from identity.config import Settings
from identity.keys import KeyRing


def mint_access_token(keys: KeyRing, settings: Settings, user_id: UUID, now: int | None = None) -> str:
    issued_at = int(time.time()) if now is None else now
    claims = {
        "sub": str(user_id),
        "iss": settings.issuer,
        "aud": settings.audience,
        "iat": issued_at,
        "exp": issued_at + settings.access_token_seconds,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, keys.signing_key, algorithm="RS256", headers={"kid": keys.signing_kid, "typ": "at+jwt"})
