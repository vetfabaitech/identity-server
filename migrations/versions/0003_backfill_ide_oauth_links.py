"""Backfill OAuth links from the IDE's users table (spec 2026-10-18 SI-5, plan 4 cutover).

Revision ID: 0003
Revises: 0002

When the identity service runs on the IDE's Supabase database (SI-2), `public.users` is the IDE's table, which records
each account's sign-in provider in `oauth_provider` / `oauth_id` (the old log-in app's model). Copying the GitHub and
Google ones into `identity.oauth_accounts` makes every existing IDE user sign straight into their own account through
the identity service, instead of being linked later by verified email.

Guarded by the columns' existence: on a database without them (the LMS's own) this does nothing. Idempotent
(`ON CONFLICT DO NOTHING`), so it can be re-run after more legacy sign-ups. Other providers ("password") are skipped:
the identity service links only GitHub and Google.

Downgrade removes nothing: links are indistinguishable from ones made at sign-in, and keeping them is harmless.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'oauth_provider')
     AND EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'oauth_id') THEN
    INSERT INTO identity.oauth_accounts (provider, provider_user_id, user_id, email_at_link)
    SELECT u.oauth_provider, u.oauth_id, u.id, left(u.email, 320)
      FROM public.users u
     WHERE u.oauth_provider IN ('github', 'google')
       AND u.oauth_id IS NOT NULL AND char_length(u.oauth_id) BETWEEN 1 AND 255
    ON CONFLICT (provider, provider_user_id) DO NOTHING;
  END IF;
END $$;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    """Keeps the links (see the module docstring)."""
