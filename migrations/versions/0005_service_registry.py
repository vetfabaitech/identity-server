"""The managed service registry and developer grants (the developer portal).

Revision ID: 0005
Revises: 0004

* `identity.services` is the registry's source of truth once this is applied. `IDENTITY_SERVICES` only seeds it
  (identity/registry_store.py `bootstrap`): a missing service is inserted, an existing one is never overwritten.
* Only the SHA-256 of a service's redemption secret is stored (plus, for a rotation grace window, the previous one).
* There is deliberately no DELETE grant: a service is disabled, never removed, so its audit trail and ownership stay.
  `owner_user_id` is ON DELETE SET NULL: removing an account never removes a service, and a service never removes one.
* `identity.developer_grants` lets an administrator delegate registering services in `local` or `staging` to a person.
  It grants no administrator rights and no production rights.
* The audit action list gains the registry actions.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
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
"""

# Data-destroying by nature: the managed registry (including every service registered through the portal) and the
# developer grants go, and audit rows with the new actions are removed so the narrower constraint can be restored.
# Services seeded from IDENTITY_SERVICES come back at the next start. Back up identity.services first.
DOWNGRADE_SQL = """
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
  'handoff_issued', 'handoff_redeemed', 'handoff_rejected'));
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
