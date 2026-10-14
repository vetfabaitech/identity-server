"""Alembic environment for the identity service: schema `identity`, plus the columns it owns on `public.users`.

The version table lives in `identity`, so these migrations and the LMS's (`lms.alembic_version`) never collide.
Run as the schema owner (the migration job), never as the service login: IDENTITY_DATABASE_URL in that job, or
`-x url=...`.
"""

import os

from alembic import context
from sqlalchemy import create_engine, pool, text

SCHEMA = "identity"


def _url() -> str:
    url = context.get_x_argument(as_dictionary=True).get("url") or os.environ.get("IDENTITY_DATABASE_URL")
    if not url:
        raise RuntimeError("Set IDENTITY_DATABASE_URL (or pass -x url=...) to run migrations.")
    scheme, sep, rest = url.partition("://")
    if scheme in ("postgresql", "postgres", "postgresql+asyncpg"):
        scheme = "postgresql+psycopg"
    return f"{scheme}{sep}{rest}"


if context.is_offline_mode():
    context.configure(url=_url(), version_table_schema=SCHEMA, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}"))
        connection.commit()
        context.configure(connection=connection, version_table_schema=SCHEMA, transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()
