"""Seed synthetic accounts for the identity load tests (load/README.md). LOCAL databases only.

Creates N approved accounts `load-NNNN@load.vetfab.local` with password LOAD_PASSWORD (one argon2id hash, reused:
the verify cost is the same), and one live refresh session per account, written to SESSIONS_OUT as JSON so the
renewal tests start with signed-in users without paying for N password checks first. Re-running replaces both.

    LOAD_DATABASE_URL=postgresql://identity:identity-local-only@127.0.0.1:54331/identity_load LOAD_PASSWORD=... \
      uv run python load/seed.py --users 1000 --sessions-out /tmp/sessions.json
"""

import argparse
import json
import os
import sys
import uuid
from urllib.parse import urlparse

import psycopg

from identity.passwords import hash_password
from identity.sessions import new_token, token_hash


def email(n: int) -> str:
    return f"load-{n:04d}@load.vetfab.local"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=1000)
    parser.add_argument("--sessions-out", required=True)
    args = parser.parse_args()
    url, password = os.environ.get("LOAD_DATABASE_URL", ""), os.environ.get("LOAD_PASSWORD", "")
    if urlparse(url).hostname not in ("127.0.0.1", "localhost") or not password:
        print("Set LOAD_DATABASE_URL (a loopback database) and LOAD_PASSWORD.", file=sys.stderr)
        return 2
    hashed = hash_password(password)
    sessions: list[dict[str, str]] = []
    with psycopg.connect(url, autocommit=False) as conn:
        rows = conn.execute(
            """INSERT INTO public.users (email, display_name, status, password_hash)
               SELECT e, 'Load ' || e, 'approved', %s FROM unnest(%s::text[]) AS e
               ON CONFLICT (email) DO UPDATE SET status = 'approved', password_hash = EXCLUDED.password_hash
               RETURNING id, email""",
            (hashed, [email(n) for n in range(1, args.users + 1)]),
        ).fetchall()
        ids = {e: i for i, e in rows}
        conn.execute("DELETE FROM identity.refresh_tokens WHERE user_id = ANY(%s)", (list(ids.values()),))
        conn.execute("DELETE FROM identity.signin_attempts")
        with conn.cursor() as cur:
            for n in range(1, args.users + 1):
                raw = new_token()
                cur.execute(
                    """INSERT INTO identity.refresh_tokens (family_id, user_id, token_hash, expires_at, user_agent)
                       VALUES (%s, %s, %s, now() + interval '30 days', 'k6-seed')""",
                    (uuid.uuid4(), ids[email(n)], token_hash(raw)),
                )
                sessions.append({"email": email(n), "refresh": raw})
        conn.commit()
    with open(args.sessions_out, "w") as out:
        json.dump(sessions, out)
    print(f"{len(ids)} accounts, {len(sessions)} sessions -> {args.sessions_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
