"""The user feed: per-user versions and an ordered change log of the fields products keep a copy of (CONTRACT.md).

Revision ID: 0006
Revises: 0005

* `public.users` is written by this service, by the IDE directly (its admin console sets `status`, its profile page
  other columns, through PostgREST as `service_role`) and possibly by the Supabase dashboard. Change capture is
  therefore a trigger, not application code: every committed change to `email`, `display_name` or `status` (only when
  the value really changes), every new row and every delete appends one row to `identity.user_events` and bumps the
  user's `identity.user_versions.version`. Changes to any other column fire nothing.
* `identity.user_versions` has deliberately no foreign key to `public.users`: a row outlives its user, so a deleted
  user's version keeps increasing if the id ever comes back. Existing users are backfilled to version 1, and a row
  that is missing anyway (a user written while the triggers were disabled) counts as version 1.
* Ordering: the trigger takes `pg_advisory_xact_lock(5279438479318730070)` (0x4944555345524556, ASCII "IDUSEREV")
  before it allocates a `seq`, so seq allocation and commit are serialised among user-identity writes (rare: sign-ups,
  status and name changes). A transaction holds the lock until it commits, and its commit is visible before the lock
  is released, so events become visible in seq order: a reader that sees seq N sees every committed event below N.
  `seq` can skip values (a rolled-back write burns one); it never goes backwards.
* The trigger function is SECURITY DEFINER with `search_path = pg_catalog, pg_temp` and only schema-qualified names,
  owned by the migration owner (on Supabase `postgres`, which owns `public.users` without being a superuser), so it
  works whoever writes: `identity_app`, the IDE's `service_role`, `postgres`. Nobody else gets a privilege on it.
  It is small on purpose: a failure here rolls back the writer's own change.
* `identity.purge_user_events(retention_days, max_rows)` (SECURITY DEFINER, EXECUTE for `identity_app` only) deletes
  a bounded batch of events older than the retention (never less than 7 days), always a prefix by seq and never the
  newest event, so `max(seq)` stays the feed head and a consumer can detect a purged gap from the lowest retained seq.
* RLS on both tables (`ENABLE ROW LEVEL SECURITY` on `identity.user_versions` and `identity.user_events`) with a
  SELECT-only policy scoped `TO identity_app` with `USING (true)`, as in 0001: the service serves every user's record
  to the products that consume the feed, so it must see every row; no other role has a policy. `identity_app` gets
  SELECT and nothing else: it cannot write or delete events except through the purge function. `anon`,
  `authenticated` and `service_role` get nothing.
* Platform-wide like every identity table, not tenant data: an account exists before and across organisations, so
  neither table carries an `org_id` (0001).
* The downgrade drops both tables (data-destroying, see DOWNGRADE_SQL): there is nothing to back up that the
  products cannot rebuild from the user list, but they must reset their cursor and versions.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# pg_advisory_xact_lock key that serialises user-event writers (CONTRACT.md, "User feed"). ASCII "IDUSEREV".
USER_EVENTS_LOCK = 0x4944555345524556

UPGRADE_SQL = """
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
"""

# Data-destroying by nature: the change log and every user's version go. Products that consume the feed must start
# over (reconcile from the user list) after a downgrade and upgrade: versions and seq restart at 1.
DOWNGRADE_SQL = """
DROP TRIGGER identity_user_event_delete ON public.users;
DROP TRIGGER identity_user_event_update ON public.users;
DROP TRIGGER identity_user_event_insert ON public.users;
DROP FUNCTION identity.purge_user_events(integer, integer);
DROP FUNCTION identity.record_user_event();
DROP TABLE identity.user_events;
DROP TABLE identity.user_versions;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
