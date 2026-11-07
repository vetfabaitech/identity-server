-- =====================================================================================================================
-- Vetfab identity service: UPGRADE an existing identity schema to the current version (0006).
-- For a Supabase project that ALREADY has the `identity` schema (the earlier LMS-era identity service created it on the
-- same project the IDE uses). For a project with no identity schema at all, run supabase-identity.sql instead.
--
-- HOW TO RUN: Supabase Dashboard -> SQL Editor -> paste this whole file -> Run. Back up first (Database -> Backups).
-- Safe to run again: it reads identity.alembic_version and applies only the steps that are missing (0001..0005 -> 0006);
-- at 0006 it does nothing. If the installed version is not one of 0001-0006 it stops and tells you which it found.
--
-- WHAT IT ADDS (additive; nothing is dropped, no row is changed)
--   * 0004  identity.handoff_tickets (one-time SSO hand-off tickets) + 3 audit actions
--   * 0005  identity.services and identity.developer_grants (the managed service registry, used by the developer portal)
--           + 10 audit actions
--   * 0006  identity.user_versions and identity.user_events (the user feed), three triggers on public.users and the
--           purge function. Every existing account gets version 1; no row of public.users changes. From then on every
--           new or deleted account and every change to email, display_name or status, whoever makes it (the IDE
--           included), also writes one event. The step briefly locks public.users against writes while it runs.
--   * public.users: oauth_provider, oauth_id, username become NULLABLE if they are not already (harmless if done).
-- The current identity service keeps working while this runs and after it: it does not use the new tables.
--
-- UNDO: supabase-identity-rollback-0006.sql (removes only 0006), then supabase-identity-rollback.sql (0004-0005).
-- =====================================================================================================================

-- 1. Checks. Nothing below runs if one fails.
DO $$
DECLARE found text;
BEGIN
  IF to_regclass('identity.alembic_version') IS NULL THEN
    RAISE EXCEPTION 'No identity schema here (identity.alembic_version is missing). Run supabase-identity.sql instead.';
  END IF;
  SELECT version_num INTO found FROM identity.alembic_version LIMIT 1;
  IF found IS NULL OR found NOT IN ('0001', '0002', '0003', '0004', '0005', '0006') THEN
    RAISE EXCEPTION 'Unexpected identity migration version: %. This script upgrades 0001..0005 to 0006; send this value to the developers.', coalesce(found, '(empty)');
  END IF;
  RAISE NOTICE 'identity schema is at version %', found;
END $$;

-- 2. Let the IDE's users table hold accounts the identity service creates (no GitHub/Google link, no username yet).
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

-- 3. The missing migrations, in order, in one block (all or nothing).
DO $mig$
DECLARE v text;
BEGIN
  SELECT version_num INTO v FROM identity.alembic_version LIMIT 1;
  IF v = '0001' THEN
    -- migration 0001 -> 0002
    EXECUTE $sql$
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
  'oauth_signin', 'oauth_linked', 'admin_bootstrapped'));
    $sql$;
    UPDATE identity.alembic_version SET version_num = '0002';
    v := '0002';
    RAISE NOTICE 'identity schema upgraded to 0002';
  END IF;
  IF v = '0002' THEN
    -- migration 0002 -> 0003
    EXECUTE $sql$
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
    $sql$;
    UPDATE identity.alembic_version SET version_num = '0003';
    v := '0003';
    RAISE NOTICE 'identity schema upgraded to 0003';
  END IF;
  IF v = '0003' THEN
    -- migration 0003 -> 0004
    EXECUTE $sql$
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
  'handoff_issued', 'handoff_redeemed', 'handoff_rejected'));
    $sql$;
    UPDATE identity.alembic_version SET version_num = '0004';
    v := '0004';
    RAISE NOTICE 'identity schema upgraded to 0004';
  END IF;
  IF v = '0004' THEN
    -- migration 0004 -> 0005
    EXECUTE $sql$
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
  'developer_granted', 'developer_revoked', 'admin_denied'));
    $sql$;
    UPDATE identity.alembic_version SET version_num = '0005';
    v := '0005';
    RAISE NOTICE 'identity schema upgraded to 0005';
  END IF;
  IF v = '0005' THEN
    -- migration 0005 -> 0006
    EXECUTE $sql$
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
GRANT EXECUTE ON FUNCTION identity.purge_user_events(integer, integer) TO identity_app;
    $sql$;
    UPDATE identity.alembic_version SET version_num = '0006';
    v := '0006';
    RAISE NOTICE 'identity schema upgraded to 0006';
  END IF;
  IF v = '0006' AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'identity' AND c.relname = 'services') THEN
    RAISE EXCEPTION 'Version says 0006 but identity.services is missing; the schema is inconsistent. Send this to the developers.';
  END IF;
  IF v = '0006' AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.users'::regclass AND tgname = 'identity_user_event_update') THEN
    RAISE EXCEPTION 'Version says 0006 but the user-feed triggers on public.users are missing; the schema is inconsistent. Send this to the developers.';
  END IF;
END $mig$;

-- 4. Check (run separately afterwards): expect version 0006 and these 10 tables.
--    select version_num from identity.alembic_version;
--    select table_name from information_schema.tables where table_schema = 'identity' order by 1;
