"""Identity service schema: users it signs in, refresh sessions, sign-in rate limit, audit.

Revision ID: 0001
Revises: (none)

* `public.users` is the identity service's table (ADR-0001: the LMS reads it only through `lms.current_identity()` and
  other SECURITY DEFINER functions). It is created only when absent: a database that already holds the LMS dev stub
  (infra/local/postgres-init) or the IDE's users table keeps its rows and columns. This revision adds only the
  columns the identity service owns (`password_hash`, `email_verified_at`, `last_login_at`), so its downgrade can
  never drop a column another service created.
* `identity_app` (NOLOGIN, NOINHERIT, NOBYPASSRLS) is the role the service runs as (`SET ROLE identity_app`); the
  login an operator creates is a member of it and nothing else (docs/operations/runbooks/database-roles.md).
* These tables are platform-wide by design, not tenant data: an account and its sessions exist before and across
  organisations, so they carry no `org_id` (the LMS's own `organisations` sit above them, not around them).
* RLS is enabled on every table. The policies are scoped `TO identity_app` with `USING (true)`: the service is the
  authority over accounts and must see every one to sign it in; no other role has a policy, so every other role
  (including `lms_app`) sees no rows. The audit log grants only SELECT and INSERT: append-only for the service.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'identity_app') THEN
    CREATE ROLE identity_app NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  display_name text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'suspended')),
  role text NOT NULL DEFAULT 'beta_user' CHECK (role IN ('admin', 'beta_user')),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS password_hash text,
  ADD COLUMN IF NOT EXISTS email_verified_at timestamptz,
  ADD COLUMN IF NOT EXISTS last_login_at timestamptz;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_key ON public.users (lower(email));

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'users'
                  AND policyname = 'users_identity_service') THEN
    CREATE POLICY users_identity_service ON public.users FOR ALL TO identity_app USING (true) WITH CHECK (true);
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO identity_app;
GRANT SELECT, INSERT, UPDATE ON public.users TO identity_app;

GRANT USAGE ON SCHEMA identity TO identity_app;

CREATE TABLE identity.refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  rotated_at timestamptz,
  revoked_at timestamptz,
  revoked_reason text CHECK (revoked_reason IN ('logout', 'reuse', 'inactive', 'admin', 'password')),
  user_agent text CHECK (char_length(user_agent) <= 512)
);
CREATE INDEX refresh_tokens_family_idx ON identity.refresh_tokens (family_id);
CREATE INDEX refresh_tokens_live_user_idx ON identity.refresh_tokens (user_id) WHERE revoked_at IS NULL;
ALTER TABLE identity.refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY refresh_tokens_identity_service ON identity.refresh_tokens FOR ALL TO identity_app
  USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON identity.refresh_tokens TO identity_app;

-- Fixed-window failure counters, keyed by `email:<address>`, `ip:<address>` or `pass:<address>`.
CREATE TABLE identity.signin_attempts (
  key text PRIMARY KEY CHECK (char_length(key) <= 400),
  window_start timestamptz NOT NULL,
  count integer NOT NULL CHECK (count >= 0)
);
ALTER TABLE identity.signin_attempts ENABLE ROW LEVEL SECURITY;
CREATE POLICY signin_attempts_identity_service ON identity.signin_attempts FOR ALL TO identity_app
  USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON identity.signin_attempts TO identity_app;

CREATE TABLE identity.audit (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT now(),
  action text NOT NULL CHECK (action IN ('signin', 'signin_failed', 'refresh', 'logout', 'revoke', 'reuse_detected',
                                         'test_signin', 'status_change', 'password_set', 'user_created')),
  user_id uuid,
  actor_id uuid,
  ip text CHECK (char_length(ip) <= 64),
  user_agent text CHECK (char_length(user_agent) <= 512),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_user_at_idx ON identity.audit (user_id, at DESC);
ALTER TABLE identity.audit ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_identity_service_select ON identity.audit FOR SELECT TO identity_app USING (true);
CREATE POLICY audit_identity_service_insert ON identity.audit FOR INSERT TO identity_app WITH CHECK (true);
GRANT SELECT, INSERT ON identity.audit TO identity_app;
"""

# Data-destroying by nature: refresh sessions, rate-limit counters, the identity audit log and stored password
# hashes go. `public.users` itself and its rows stay (it may predate this revision), as does the `identity_app` role
# (cluster-wide, possibly granted to logins in other databases).
DOWNGRADE_SQL = """
DROP TABLE identity.audit;
DROP TABLE identity.signin_attempts;
DROP TABLE identity.refresh_tokens;
REVOKE USAGE ON SCHEMA identity FROM identity_app;

DROP POLICY IF EXISTS users_identity_service ON public.users;
REVOKE SELECT, INSERT, UPDATE ON public.users FROM identity_app;
DROP INDEX IF EXISTS public.users_email_lower_key;
ALTER TABLE public.users
  DROP COLUMN IF EXISTS password_hash,
  DROP COLUMN IF EXISTS email_verified_at,
  DROP COLUMN IF EXISTS last_login_at;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
