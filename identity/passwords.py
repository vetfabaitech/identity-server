"""Password hashing with argon2id (argon2-cffi defaults).

`verify_password` costs the same whether or not the account exists or has a password: an unknown email is checked
against a dummy hash, so response time does not reveal which emails have accounts.
"""

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Upper bound on accepted input; argon2 would hash anything, but a megabyte password is only a cost to us.
MAX_PASSWORD_LENGTH = 256
MIN_PASSWORD_LENGTH = 10

_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(f"Passwords are {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_LENGTH} characters.")
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    candidate = password[:MAX_PASSWORD_LENGTH]
    try:
        matched = _hasher.verify(stored_hash or _DUMMY_HASH, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return matched and stored_hash is not None and len(password) <= MAX_PASSWORD_LENGTH
