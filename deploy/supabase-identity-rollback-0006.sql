-- Removes ONLY migration 0006 (the user feed): the triggers on public.users, identity.user_events, identity.user_versions
-- and the purge function. Every product that reads the feed must then start over (reconcile from the user list), because
-- versions and seq restart at 1 if 0006 is applied again. User accounts and the IDE's tables are not touched.
-- Run it on a schema at 0006 (it stops otherwise). Generated with: alembic downgrade 0006:0005 --sql
DO $$
DECLARE found text;
BEGIN
  SELECT version_num INTO found FROM identity.alembic_version LIMIT 1;
  IF found IS DISTINCT FROM '0006' THEN
    RAISE EXCEPTION 'This script removes migration 0006, but the identity schema is at %. Nothing was changed.', coalesce(found, '(empty)');
  END IF;
END $$;

BEGIN;

-- Running downgrade 0006 -> 0005

DROP TRIGGER identity_user_event_delete ON public.users;
DROP TRIGGER identity_user_event_update ON public.users;
DROP TRIGGER identity_user_event_insert ON public.users;
DROP FUNCTION identity.purge_user_events(integer, integer);
DROP FUNCTION identity.record_user_event();
DROP TABLE identity.user_events;
DROP TABLE identity.user_versions;;

UPDATE identity.alembic_version SET version_num='0005' WHERE identity.alembic_version.version_num = '0006';

COMMIT;
