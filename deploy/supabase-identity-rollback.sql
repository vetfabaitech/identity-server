-- Removes ONLY migrations 0004-0005 (hand-off tickets, the managed service registry, developer grants) and their audit rows.
-- ALL services registered in the developer portal are lost (copy identity.services out first). User accounts, sessions and
-- the IDE's tables are not touched. Generated with: alembic downgrade 0005:0003 --sql
-- Run it on a schema at 0005 (it stops otherwise): on one at 0006, run supabase-identity-rollback-0006.sql first.
DO $$
DECLARE found text;
BEGIN
  SELECT version_num INTO found FROM identity.alembic_version LIMIT 1;
  IF found IS DISTINCT FROM '0005' THEN
    RAISE EXCEPTION 'This script removes migrations 0004-0005 from a schema at 0005, but it is at %. Nothing was changed (at 0006, run supabase-identity-rollback-0006.sql first).', coalesce(found, '(empty)');
  END IF;
END $$;

BEGIN;

-- Running downgrade 0005 -> 0004

DROP TABLE identity.developer_grants;
DROP TABLE identity.services;
ALTER TABLE identity.audit DROP CONSTRAINT audit_action_check;
DELETE FROM identity.audit WHERE action IN (
  'service_created', 'service_updated', 'service_status_changed', 'service_secret_issued',
  'service_secret_rotated', 'service_secret_revoked', 'service_bootstrapped',
  'developer_granted', 'developer_revoked', 'admin_denied');
ALTER TABLE identity.audit ADD CONSTRAINT audit_action_check CHECK (action IN (
  'signin', 'signin_failed', 'refresh', 'logout', 'revoke', 'reuse_detected',
  'test_signin', 'status_change', 'password_set', 'user_created',
  'oauth_signin', 'oauth_linked', 'admin_bootstrapped',
  'handoff_issued', 'handoff_redeemed', 'handoff_rejected'));;

UPDATE identity.alembic_version SET version_num='0004' WHERE identity.alembic_version.version_num = '0005';

-- Running downgrade 0004 -> 0003

DROP TABLE identity.handoff_tickets;
ALTER TABLE identity.audit DROP CONSTRAINT audit_action_check;
DELETE FROM identity.audit WHERE action IN ('handoff_issued', 'handoff_redeemed', 'handoff_rejected');
ALTER TABLE identity.audit ADD CONSTRAINT audit_action_check CHECK (action IN (
  'signin', 'signin_failed', 'refresh', 'logout', 'revoke', 'reuse_detected',
  'test_signin', 'status_change', 'password_set', 'user_created',
  'oauth_signin', 'oauth_linked', 'admin_bootstrapped'));;

UPDATE identity.alembic_version SET version_num='0003' WHERE identity.alembic_version.version_num = '0004';

COMMIT;

