"""`identity-admin`: operator commands for the identity service (spec §3.5).

Runs with the service's own settings (IDENTITY_*) and, like the service, as `identity_app`. Every account change is
written to identity.audit. Passwords are read from stdin (`--password-stdin`) or prompted for, never taken as
arguments, so they stay out of shell history and process listings.

    identity-admin ensure-key | rotate-key
    identity-admin create-user --email E --name N [--status approved|pending] [--password-stdin]
    identity-admin set-password EMAIL [--password-stdin]
    identity-admin set-status EMAIL pending|approved|rejected|suspended
    identity-admin token EMAIL                 # a 15-minute access token for scripts (content import)
    identity-admin seed-test-accounts          # IDENTITY_TEST_ACCOUNTS_PASSWORD on every listed test account
    identity-admin revoke-sessions EMAIL
    identity-admin service-secret              # a hand-off redemption secret and its hash for IDENTITY_SERVICES
"""

import argparse
import asyncio
import getpass
import hashlib
import secrets
import sys
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from typing import Any, cast

import psycopg

from identity import sessions, store
from identity.config import Settings, get_settings
from identity.db import RUNTIME_ROLE
from identity.keys import KeyRing, NoSigningKeyError, generate_key
from identity.passwords import hash_password
from identity.store import STATUSES, Status
from identity.tokens import mint_access_token

OK, NOT_FOUND, REFUSED = 0, 1, 2


class CliError(Exception):
    def __init__(self, message: str, code: int = REFUSED) -> None:
        super().__init__(message)
        self.code = code


@asynccontextmanager
async def _connection(settings: Settings) -> AsyncIterator[psycopg.AsyncConnection[Any]]:
    async with await psycopg.AsyncConnection.connect(settings.database_url) as conn:
        await conn.execute(f"SET ROLE {RUNTIME_ROLE}")
        async with conn.transaction():
            yield conn


async def _user(conn: psycopg.AsyncConnection[Any], email: str) -> store.User:
    user = await store.find_user_by_email(conn, email)
    if user is None:
        raise CliError(f"No account with email {email.strip()}.", NOT_FOUND)
    return user


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Again: "):
        raise CliError("The passwords do not match.")
    return first


def _hash(password: str) -> str:
    try:
        return hash_password(password)
    except ValueError as exc:
        raise CliError(str(exc)) from exc


# --------------------------------------------------------------------------- commands


async def ensure_key(settings: Settings, _: argparse.Namespace) -> None:
    try:
        kid = KeyRing.load(settings.keys_dir).signing_kid
        print(f"Signing key already present: {kid}")
    except NoSigningKeyError:
        print(f"Generated signing key {generate_key(settings.keys_dir)}")


async def rotate_key(settings: Settings, _: argparse.Namespace) -> None:
    kid = generate_key(settings.keys_dir)
    print(f"Restart the service to sign with the new key. Delete older keys 15 minutes after that. New key: {kid}")


async def create_user(settings: Settings, args: argparse.Namespace) -> None:
    password_hash = _hash(_read_password(True)) if args.password_stdin else None
    async with _connection(settings) as conn:
        if await store.find_user_by_email(conn, args.email):
            raise CliError(f"An account with email {args.email.strip()} already exists.")
        user = await store.create_user(conn, args.email, args.name, cast(Status, args.status))
        if password_hash:
            await store.set_password(conn, user.id, password_hash)
        await store.audit(conn, "user_created", user_id=user.id, metadata={"via": "cli", "status": args.status})
    print(f"Created {user.email} ({user.id}), status {user.status}.")


async def set_password(settings: Settings, args: argparse.Namespace) -> None:
    password_hash = _hash(_read_password(args.password_stdin))
    async with _connection(settings) as conn:
        user = await _user(conn, args.email)
        await store.set_password(conn, user.id, password_hash)
        revoked = await sessions.revoke_user(conn, user.id, "password")
        await store.audit(conn, "password_set", user_id=user.id, metadata={"via": "cli", "sessions_revoked": revoked})
    print(f"Password set for {user.email}; {revoked} session(s) signed out.")


async def set_status(settings: Settings, args: argparse.Namespace) -> None:
    async with _connection(settings) as conn:
        user = await _user(conn, args.email)
        await store.set_status(conn, user.id, args.status)
        revoked = 0 if args.status in store.ACTIVE_STATUSES else await sessions.revoke_user(conn, user.id, "admin")
        await store.audit(
            conn, "status_change", user_id=user.id, metadata={"via": "cli", "from": user.status, "to": args.status}
        )
    print(f"{user.email}: {user.status} -> {args.status}; {revoked} session(s) signed out.")


async def token(settings: Settings, args: argparse.Namespace) -> None:
    keys = KeyRing.load(settings.keys_dir)
    async with _connection(settings) as conn:
        user = await _user(conn, args.email)
        await store.audit(conn, "signin", user_id=user.id, metadata={"via": "cli-token"})
    print(mint_access_token(keys, settings, user.id))


async def seed_test_accounts(settings: Settings, _: argparse.Namespace) -> None:
    if settings.environment == "production":
        raise CliError("seed-test-accounts is refused in production.")
    if settings.test_accounts_password is None:
        raise CliError("Set IDENTITY_TEST_ACCOUNTS_PASSWORD first.")
    password_hash = _hash(settings.test_accounts_password.get_secret_value())
    emails = settings.test_account_emails
    async with _connection(settings) as conn:
        found = await store.list_users_by_emails(conn, emails)
        for user in found:
            await store.set_password(conn, user.id, password_hash)
            await store.audit(conn, "password_set", user_id=user.id, metadata={"via": "seed-test-accounts"})
    missing = sorted(set(emails) - {store.normalise_email(u.email) for u in found})
    print(f"Password set on {len(found)} account(s).")
    if missing:
        print("Not found (run the LMS seed first): " + ", ".join(missing))


async def revoke_sessions(settings: Settings, args: argparse.Namespace) -> None:
    async with _connection(settings) as conn:
        user = await _user(conn, args.email)
        revoked = await sessions.revoke_user(conn, user.id, "admin")
        await store.audit(conn, "revoke", user_id=user.id, metadata={"via": "cli", "sessions": revoked})
    print(f"{revoked} session(s) of {user.email} signed out.")


async def service_secret(_: Settings, __: argparse.Namespace) -> None:
    """A redemption secret for a service and the hash that goes in IDENTITY_SERVICES. Touches no database."""
    secret = secrets.token_urlsafe(32)
    print(f"VETFAB_SERVICE_SECRET={secret}   # give to the service, keep it server-side")
    print(f'"secret_sha256": "{hashlib.sha256(secret.encode()).hexdigest()}"   # goes in IDENTITY_SERVICES')


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="identity-admin", description="Vetfab identity service administration.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ensure-key", help="generate a signing key if none exists").set_defaults(run=ensure_key)
    sub.add_parser("rotate-key", help="add a new signing key").set_defaults(run=rotate_key)
    p = sub.add_parser("create-user", help="create an account")
    p.add_argument("--email", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--status", choices=STATUSES, default="approved")
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(run=create_user)
    p = sub.add_parser("set-password", help="set an account's password (signs out its sessions)")
    p.add_argument("email")
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(run=set_password)
    p = sub.add_parser("set-status", help="approve, suspend, reject or reset an account")
    p.add_argument("email")
    p.add_argument("status", choices=STATUSES)
    p.set_defaults(run=set_status)
    p = sub.add_parser("token", help="print a 15-minute access token for scripts")
    p.add_argument("email")
    p.set_defaults(run=token)
    sub.add_parser("seed-test-accounts", help="set the test password on the listed test accounts").set_defaults(
        run=seed_test_accounts
    )
    sub.add_parser("service-secret", help="make a hand-off redemption secret and its registry hash").set_defaults(
        run=service_secret
    )
    p = sub.add_parser("revoke-sessions", help="sign an account out everywhere")
    p.add_argument("email")
    p.set_defaults(run=revoke_sessions)
    return parser


def main(argv: list[str] | None = None, *, settings: Settings | None = None) -> int:
    args = _parser().parse_args(argv)
    command = cast(Callable[[Settings, argparse.Namespace], Coroutine[Any, Any, None]], args.run)
    try:
        asyncio.run(command(settings or get_settings(), args))
    except CliError as exc:
        print(f"identity-admin: {exc}", file=sys.stderr)
        return exc.code
    return OK


if __name__ == "__main__":
    sys.exit(main())
