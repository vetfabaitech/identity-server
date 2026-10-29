"""Helpers for dev/open-portal.ps1: seed a local administrator and serve the identity service on Windows.

Local development only: the database is the throwaway compose Postgres and the credentials below are public.

    python dev/portal_dev.py seed    # an approved administrator in the dev database
    python dev/portal_dev.py serve   # the identity service on :8200 (selector event loop: psycopg needs it on Windows)
"""

import asyncio
import selectors
import sys

DATABASE = "postgresql://identity:identity-local-only@127.0.0.1:54331/identity"
ADMIN_EMAIL = "admin@dev.vetfab.local"
ADMIN_PASSWORD = "correct horse battery"  # noqa: S105  # local dev only


def seed() -> None:
    import psycopg

    from identity.passwords import hash_password

    with psycopg.connect(DATABASE, autocommit=True) as conn:
        conn.execute(
            """INSERT INTO public.users (email, display_name, status, role, password_hash)
               VALUES (%s, 'Dev Admin', 'approved', 'admin', %s)
               ON CONFLICT (email) DO UPDATE SET status = 'approved', role = 'admin',
                                                 password_hash = EXCLUDED.password_hash""",
            (ADMIN_EMAIL, hash_password(ADMIN_PASSWORD)),
        )
    print(f"administrator ready: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")


def serve() -> None:
    import uvicorn

    from identity.web.app import create_app

    config = uvicorn.Config(create_app, factory=True, host="127.0.0.1", port=8200, loop="none")
    loop_factory = lambda: asyncio.SelectorEventLoop(selectors.SelectSelector())  # noqa: E731
    asyncio.run(uvicorn.Server(config).serve(), loop_factory=loop_factory)


if __name__ == "__main__":
    {"seed": seed, "serve": serve}[sys.argv[1] if len(sys.argv) > 1 else "serve"]()
