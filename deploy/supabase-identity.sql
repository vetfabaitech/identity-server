-- =====================================================================================================================
-- Vetfab identity service: database objects for an EXISTING Supabase project (the one the IDE uses).
--
-- Generated from migrations 0001-0006 with:   alembic upgrade head --sql      (no database is contacted to make it)
-- Regenerate after a new migration:           IDENTITY_DATABASE_URL=postgresql://x@localhost/x alembic upgrade head --sql
--
-- USE THIS ONLY IF the project has NO `identity` schema yet. If it does (an earlier identity service created it on the same
-- project), run supabase-identity-upgrade.sql instead; this file refuses to run over an existing schema.
--
-- HOW TO RUN: Supabase Dashboard -> SQL Editor -> paste this whole file -> Run. ONCE. Back up first (Database -> Backups).
-- Prerequisite: the IDE's own migrations are already applied (log-in/backend/supabase_migration_users.sql and
--               supabase_migration_beta_access.sql). This script checks and stops with a message if they are not.
--
-- WHAT IT CHANGES
--   * public.users (the IDE's table; every row and column stays): oauth_provider, oauth_id and username become NULLABLE
--     (an account made by the identity service has none of them until the IDE's onboarding sets a username); adds
--     password_hash, email_verified_at, last_login_at; a unique index on lower(email); a row-level-security policy for
--     the identity service's role. Existing GitHub/Google links are copied into identity.oauth_accounts.
--     Three triggers (the user feed, migration 0006): every new or deleted account and every change to email,
--     display_name or status, whoever makes it (the IDE included), is recorded in identity.user_events.
--   * a new schema `identity`: refresh_tokens, signin_attempts, audit, oauth_accounts, handoff_tickets, services,
--     developer_grants, user_versions (every existing account at version 1), user_events, alembic_version. RLS is on for
--     every table; the role `identity_app` is the only one with a policy.
--   * the role `identity_app` (NOLOGIN) is created. The identity service connects as a login that is a member of it
--     (deploy/provision-role.sql), or, for local testing only, as the project's `postgres` user.
--
-- UNDO: deploy/supabase-identity-rollback-0006.sql removes only the user feed (migration 0006); after it,
--       deploy/supabase-identity-rollback.sql removes migrations 0004-0005 (hand-off tickets, the service registry,
--       developer grants). Removing everything is `alembic downgrade base`.
-- =====================================================================================================================

-- 1. Safety checks. Nothing below runs if any of these fails.
DO $$
BEGIN
  IF to_regclass('identity.alembic_version') IS NOT NULL THEN
    RAISE EXCEPTION 'The identity schema is already installed (identity.alembic_version exists). This file is for a project with no identity schema. Run deploy/supabase-identity-upgrade.sql instead.';
  END IF;
  IF to_regclass('public.users') IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'status')
       OR NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'role') THEN
      RAISE EXCEPTION 'public.users has no status/role columns. Run the IDE migration log-in/backend/supabase_migration_beta_access.sql first.';
    END IF;
    IF EXISTS (SELECT 1 FROM public.users GROUP BY lower(email) HAVING count(*) > 1) THEN
      RAISE EXCEPTION 'Two accounts differ only by email case. Resolve them first: select lower(email), count(*) from public.users group by 1 having count(*) > 1;';
    END IF;
  END IF;
END $$;

-- 2. Let the IDE's users table hold accounts the identity service creates (no GitHub/Google link, no username yet).
--    Harmless if already done (for example by the IDE's shared-identity migration).
DO $$
DECLARE wanted text;
BEGIN
  IF to_regclass('public.users') IS NOT NULL THEN
    FOREACH wanted IN ARRAY ARRAY['oauth_provider', 'oauth_id', 'username'] LOOP
      IF EXISTS (SELECT 1 FROM information_schema.columns c WHERE c.table_schema = 'public' AND c.table_name = 'users' AND c.column_name = wanted) THEN
        EXECUTE format('ALTER TABLE public.users ALTER COLUMN %I DROP NOT NULL', wanted);
      END IF;
    END LOOP;
  END IF;
END $$;

-- 3. The identity service's schema and tables (migrations 0001 -> 0006).
CREATE SCHEMA IF NOT EXISTS identity;

BEGIN;

CREATE TABLE identity.alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 0001

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
GRANT SELECT, INSERT ON identity.audit TO identity_app;;

INSERT INTO identity.alembic_version (version_num) VALUES ('0001') RETURNING identity.alembic_version.version_num;

-- Running upgrade 0001 -> 0002

CREATE TABLE identity.oauth_accounts (
  provider text NOT NULL CHECK (provider IN ('github', 'google')),
  provider_user_id text NOT NULL CHECK (char_length(provider_user_id) BETWEEN 1 AND 255),
  user_id uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  email_at_link text CHECK (char_length(email_at_link) <= 320),
  linked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, provider_user_id)
);
CREATE INDEX oauth_accounts_user_idx ON identity.oauth_accounts (user_id);
ALTER TABLE identity.oauth_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth_accounts_identity_service ON identity.oauth_accounts FOR ALL TO identity_app
  USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, DELETE ON identity.oauth_accounts TO identity_app;

ALTER TABLE identity.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE identity.audit ADD CONSTRAINT audit_action_check CHECK (action IN (
  'signin', 'signin_failed', 'refresh', 'logout', 'revoke', 'reuse_detected',
  'test_signin', 'status_change', 'password_set', 'user_created',
  'oauth_signin', 'oauth_linked', 'admin_bootstrapped'));;

UPDATE identity.alembic_version SET version_num='0002' WHERE identity.alembic_version.version_num = '0001';

-- Running upgrade 0002 -> 0003

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

UPDATE identity.alembic_version SET version_num='0003' WHERE identity.alembic_version.version_num = '0002';

-- Running upgrade 0003 -> 0004

CREATE TABLE identity.handoff_tickets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_hash bytea NOT NULL UNIQUE CHECK (octet_length(ticket_hash) = 32),
  family_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  source_service text NOT NULL CHECK (char_length(source_service) <= 32),
  target_service text NOT NULL CHECK (char_length(target_service) <= 32),
  return_path text NOT NULL CHECK (char_length(return_path) <= 2048),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX handoff_tickets_family_idx ON identity.handoff_tickets (family_id) WHERE consumed_at IS NULL;
CREATE INDEX handoff_tickets_expiry_idx ON identity.handoff_tickets (expires_at);
ALTER TABLE identity.handoff_tickets ENABLE ROW LEVEL SECURITY;
CREATE POLICY handoff_tickets_identity_service ON identity.handoff_tickets FOR ALL TO identity_app
  USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON identity.handoff_tickets TO identity_app;

ALTER TABLE identity.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE identity.audit ADD CONSTRAINT audit_action_check CHECK (action IN (
  'signin', 'signin_failed', 'refresh', 'logout', 'revoke', 'reuse_detected',
  'test_signin', 'status_change', 'password_set', 'user_created',
  'oauth_signin', 'oauth_linked', 'admin_bootstrapped',
  'handoff_issued', 'handoff_redeemed', 'handoff_rejected'));;

UPDATE identity.alembic_version SET version_num='0004' WHERE identity.alembic_version.version_num = '0003';

-- Running upgrade 0004 -> 0005

CREATE TABLE identity.services (
  id text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9-]{1,31}$'),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 60),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
  owner_team text NOT NULL DEFAULT '' CHECK (char_length(owner_team) <= 60),
  owner_user_id uuid REFERENCES public.users (id) ON DELETE SET NULL,
  environment text NOT NULL CHECK (environment IN ('local', 'staging', 'production')),
  base_url text NOT NULL UNIQUE CHECK (char_length(base_url) <= 255),
  callback_path text NOT NULL DEFAULT '/handoff/redeem' CHECK (char_length(callback_path) <= 130),
  roles text[] NOT NULL DEFAULT '{}' CHECK (roles <@ ARRAY['admin', 'beta_user']),
  return_path_prefixes text[] NOT NULL DEFAULT '{}' CHECK (cardinality(return_path_prefixes) <= 20),
  session_seconds integer NOT NULL DEFAULT 900 CHECK (session_seconds BETWEEN 60 AND 3600),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disabled')),
  source text NOT NULL DEFAULT 'managed' CHECK (source IN ('bootstrap', 'managed')),
  secret_sha256 text NOT NULL CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
  previous_secret_sha256 text CHECK (previous_secret_sha256 ~ '^[0-9a-f]{64}$'),
  previous_secret_expires_at timestamptz,
  secret_rotated_at timestamptz,
  created_by uuid REFERENCES public.users (id) ON DELETE SET NULL,
  approved_by uuid REFERENCES public.users (id) ON DELETE SET NULL,
  approved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX services_owner_idx ON identity.services (owner_user_id);
ALTER TABLE identity.services ENABLE ROW LEVEL SECURITY;
CREATE POLICY services_identity_service ON identity.services FOR ALL TO identity_app USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON identity.services TO identity_app;

CREATE TABLE identity.developer_grants (
  user_id uuid PRIMARY KEY REFERENCES public.users (id) ON DELETE CASCADE,
  environments text[] NOT NULL CHECK (environments <@ ARRAY['local', 'staging'] AND cardinality(environments) > 0),
  granted_by uuid REFERENCES public.users (id) ON DELETE SET NULL,
  granted_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE identity.developer_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY developer_grants_identity_service ON identity.developer_grants FOR ALL TO identity_app
  USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON identity.developer_grants TO identity_app;

ALTER TABLE identity.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE identity.audit ADD CONSTRAINT audit_action_check CHECK (action IN (
  'signin', 'signin_failed', 'refresh', 'logout', 'revoke', 'reuse_detected',
  'test_signin', 'status_change', 'password_set', 'user_created',
  'oauth_signin', 'oauth_linked', 'admin_bootstrapped',
  'handoff_issued', 'handoff_redeemed', 'handoff_rejected',
  'service_created', 'service_updated', 'service_status_changed', 'service_secret_issued',
  'service_secret_rotated', 'service_secret_revoked', 'service_bootstrapped',
  'developer_granted', 'developer_revoked', 'admin_denied'));;

UPDATE identity.alembic_version SET version_num='0005' WHERE identity.alembic_version.version_num = '0004';

-- Running upgrade 0005 -> 0006

-- No user write may slip in between the backfill and the triggers.
LOCK TABLE public.users IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE identity.user_versions (
  user_id uuid PRIMARY KEY,
  version bigint NOT NULL CHECK (version >= 1)
);
INSERT INTO identity.user_versions (user_id, version) SELECT id, 1 FROM public.users;
ALTER TABLE identity.user_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_versions_identity_service ON identity.user_versions FOR SELECT TO identity_app USING (true);
GRANT SELECT ON identity.user_versions TO identity_app;

CREATE TABLE identity.user_events (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  type text NOT NULL CHECK (type IN ('user.created', 'user.updated', 'user.deleted')),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  email text,
  display_name text,
  status text
);
CREATE INDEX user_events_occurred_at_idx ON identity.user_events (occurred_at, seq);
ALTER TABLE identity.user_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_events_identity_service ON identity.user_events FOR SELECT TO identity_app USING (true);
GRANT SELECT ON identity.user_events TO identity_app;

CREATE FUNCTION identity.record_user_event() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  next_version bigint;
BEGIN
  -- Serialises seq allocation and commit among user-identity writes, so events become visible in seq order.
  PERFORM pg_catalog.pg_advisory_xact_lock(5279438479318730070);
  IF TG_OP = 'DELETE' THEN
    INSERT INTO identity.user_versions AS v (user_id, version) VALUES (OLD.id, 2)
      ON CONFLICT (user_id) DO UPDATE SET version = v.version + 1
      RETURNING v.version INTO next_version;
    INSERT INTO identity.user_events (user_id, version, type) VALUES (OLD.id, next_version, 'user.deleted');
  ELSE
    -- A new id starts at 1; a user with no row yet (written while the triggers were off) was implicitly at 1.
    INSERT INTO identity.user_versions AS v (user_id, version)
      VALUES (NEW.id, CASE WHEN TG_OP = 'INSERT' THEN 1 ELSE 2 END)
      ON CONFLICT (user_id) DO UPDATE SET version = v.version + 1
      RETURNING v.version INTO next_version;
    INSERT INTO identity.user_events (user_id, version, type, email, display_name, status)
      VALUES (NEW.id, next_version, CASE WHEN TG_OP = 'INSERT' THEN 'user.created' ELSE 'user.updated' END,
              NEW.email, NEW.display_name, NEW.status);
  END IF;
  RETURN NULL;
END
$fn$;
REVOKE ALL ON FUNCTION identity.record_user_event() FROM PUBLIC;

CREATE TRIGGER identity_user_event_insert AFTER INSERT ON public.users
  FOR EACH ROW EXECUTE FUNCTION identity.record_user_event();
CREATE TRIGGER identity_user_event_update AFTER UPDATE OF email, display_name, status ON public.users
  FOR EACH ROW
  WHEN (OLD.email IS DISTINCT FROM NEW.email OR OLD.display_name IS DISTINCT FROM NEW.display_name
        OR OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION identity.record_user_event();
CREATE TRIGGER identity_user_event_delete AFTER DELETE ON public.users
  FOR EACH ROW EXECUTE FUNCTION identity.record_user_event();

CREATE FUNCTION identity.purge_user_events(retention_days integer, max_rows integer) RETURNS bigint
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  head bigint;
  through bigint;
  removed bigint;
BEGIN
  SELECT max(e.seq) INTO head FROM identity.user_events e;
  SELECT max(old.seq) INTO through FROM (
    SELECT e.seq FROM identity.user_events e
     WHERE e.occurred_at < pg_catalog.now() - pg_catalog.make_interval(days => GREATEST(retention_days, 7))
     ORDER BY e.occurred_at, e.seq LIMIT GREATEST(max_rows, 1)) old;
  IF through IS NULL THEN
    RETURN 0;  -- nothing has expired (LEAST below would ignore the NULL)
  END IF;
  -- A prefix by seq, and never the newest event: max(seq) stays the head, min(seq) shows a purged gap.
  through := LEAST(through, head - 1);
  IF through < 1 THEN
    RETURN 0;
  END IF;
  DELETE FROM identity.user_events e WHERE e.seq <= through;
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END
$fn$;
REVOKE ALL ON FUNCTION identity.purge_user_events(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.purge_user_events(integer, integer) TO identity_app;;

UPDATE identity.alembic_version SET version_num='0006' WHERE identity.alembic_version.version_num = '0005';

COMMIT;



-- 4. Check (run separately afterwards): expect 10 tables and version 0006.
--    select table_name from information_schema.tables where table_schema = 'identity' order by 1;
--    select version_num from identity.alembic_version;
