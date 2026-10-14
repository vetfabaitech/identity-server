"""identity-admin: key management, accounts, script tokens, test-account passwords."""

import asyncio
import io
import json
import uuid
from pathlib import Path

import psycopg
import pytest

from identity.cli import main
from identity.config import Settings
from identity.keys import KeyRing
from identity.passwords import verify_password
from tests.conftest import make_settings
from vetfab_authz.tokens import JwksKeyStore, JwksSource, TokenPolicy, TokenVerifier


@pytest.fixture
def cli_settings(login_url: str, tmp_path: Path) -> Settings:
    return make_settings(login_url, tmp_path / "keys")


def run(
    capsys: pytest.CaptureFixture[str], settings: Settings, *argv: str, stdin: str | None = None
) -> tuple[int, str]:
    if stdin is not None:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("sys.stdin", io.StringIO(stdin))
            code = main(list(argv), settings=settings)
    else:
        code = main(list(argv), settings=settings)
    return code, capsys.readouterr().out.strip()


def row(owner_url: str, email: str) -> tuple[str, str, str | None]:
    with psycopg.connect(owner_url) as conn:
        found = conn.execute(
            "SELECT id::text, status, password_hash FROM public.users WHERE email = %s", (email,)
        ).fetchone()
    assert found is not None
    return found


def test_ensure_key_creates_one_key_once(capsys: pytest.CaptureFixture[str], cli_settings: Settings) -> None:
    code, first = run(capsys, cli_settings, "ensure-key")
    assert code == 0
    code, second = run(capsys, cli_settings, "ensure-key")
    assert code == 0
    assert KeyRing.load(cli_settings.keys_dir).signing_kid in first
    assert len(list(cli_settings.keys_dir.glob("*.pem"))) == 1
    assert "already" in second


def test_rotate_key_adds_a_newer_signing_key(capsys: pytest.CaptureFixture[str], cli_settings: Settings) -> None:
    run(capsys, cli_settings, "ensure-key")
    code, out = run(capsys, cli_settings, "rotate-key")
    assert code == 0
    assert KeyRing.load(cli_settings.keys_dir).signing_kid == out.split()[-1]
    assert len(list(cli_settings.keys_dir.glob("*.pem"))) == 2


@pytest.mark.db
def test_create_user_and_set_password(
    capsys: pytest.CaptureFixture[str], cli_settings: Settings, owner_url: str
) -> None:
    email = f"cli-{uuid.uuid4().hex[:8]}@dev.vetfab.local"
    code, _ = run(capsys, cli_settings, "create-user", "--email", email.upper(), "--name", "Cli User")
    assert code == 0
    _, status, hashed = row(owner_url, email)
    assert status == "approved" and hashed is None
    code, _ = run(capsys, cli_settings, "set-password", email, "--password-stdin", stdin="a sturdy password\n")
    assert code == 0
    assert verify_password(row(owner_url, email)[2], "a sturdy password")


@pytest.mark.db
def test_short_passwords_are_refused(
    capsys: pytest.CaptureFixture[str], cli_settings: Settings, owner_url: str
) -> None:
    email = f"cli-{uuid.uuid4().hex[:8]}@dev.vetfab.local"
    run(capsys, cli_settings, "create-user", "--email", email, "--name", "Cli User")
    code, _ = run(capsys, cli_settings, "set-password", email, "--password-stdin", stdin="short\n")
    assert code == 2
    assert row(owner_url, email)[2] is None


@pytest.mark.db
def test_token_prints_a_verified_token(
    capsys: pytest.CaptureFixture[str], cli_settings: Settings, owner_url: str, tmp_path: Path
) -> None:
    email = f"cli-{uuid.uuid4().hex[:8]}@dev.vetfab.local"
    run(capsys, cli_settings, "create-user", "--email", email, "--name", "Cli User")
    run(capsys, cli_settings, "ensure-key")
    code, token = run(capsys, cli_settings, "token", email)
    assert code == 0
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps(KeyRing.load(cli_settings.keys_dir).jwks()))
    verifier = TokenVerifier(
        TokenPolicy(issuer=cli_settings.issuer, audience=cli_settings.audience), JwksKeyStore(JwksSource(file=jwks))
    )
    assert str(asyncio.run(verifier.verify(token)).user_id) == row(owner_url, email)[0]


@pytest.mark.db
def test_token_for_an_unknown_email_fails(capsys: pytest.CaptureFixture[str], cli_settings: Settings) -> None:
    run(capsys, cli_settings, "ensure-key")
    code, out = run(capsys, cli_settings, "token", "nobody@nowhere.test")
    assert code == 1 and out == ""


@pytest.mark.db
def test_suspending_revokes_sessions(
    capsys: pytest.CaptureFixture[str], cli_settings: Settings, owner_url: str
) -> None:
    email = f"cli-{uuid.uuid4().hex[:8]}@dev.vetfab.local"
    run(capsys, cli_settings, "create-user", "--email", email, "--name", "Cli User")
    user_id = row(owner_url, email)[0]
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute(
            """INSERT INTO identity.refresh_tokens (family_id, user_id, token_hash, expires_at)
               VALUES (gen_random_uuid(), %s, decode(md5(random()::text) || md5(random()::text), 'hex'),
                       now() + interval '1 day')""",
            (user_id,),
        )
    code, _ = run(capsys, cli_settings, "set-status", email, "suspended")
    assert code == 0
    assert row(owner_url, email)[1] == "suspended"
    with psycopg.connect(owner_url) as conn:
        live = conn.execute(
            "SELECT count(*) FROM identity.refresh_tokens WHERE user_id = %s AND revoked_at IS NULL", (user_id,)
        ).fetchone()
    assert live == (0,)


@pytest.mark.db
def test_seed_test_accounts_sets_the_configured_password(
    capsys: pytest.CaptureFixture[str], login_url: str, tmp_path: Path, owner_url: str
) -> None:
    present = f"seed-{uuid.uuid4().hex[:8]}@dev.vetfab.local"
    settings = make_settings(
        login_url,
        tmp_path,
        test_accounts=True,
        test_accounts_passphrase="a long enough passphrase",
        test_accounts_emails=f"{present},absent-{uuid.uuid4().hex[:8]}@dev.vetfab.local",
        test_accounts_password="testers password 1",
    )
    run(capsys, settings, "create-user", "--email", present, "--name", "Seeded")
    code, out = run(capsys, settings, "seed-test-accounts")
    assert code == 0
    assert "1 account" in out and "absent-" in out
    assert verify_password(row(owner_url, present)[2], "testers password 1")


def test_seed_test_accounts_is_refused_in_production(
    capsys: pytest.CaptureFixture[str], login_url: str, tmp_path: Path
) -> None:
    settings = make_settings(login_url, tmp_path, environment="production", test_accounts_password="testers password 1")
    code, _ = run(capsys, settings, "seed-test-accounts")
    assert code == 2
