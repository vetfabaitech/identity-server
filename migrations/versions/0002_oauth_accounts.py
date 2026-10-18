"""OAuth account links: which GitHub or Google identity signs in as which user (spec SI-5).

Revision ID: 0002
Revises: 0001

* `identity.oauth_accounts` maps a provider's stable user id to a `public.users` row. Links live here, never as
  columns on `users` (spec TD-8), so the users table stays shared with the IDE without identity-specific columns.
* Platform-wide like every identity table: an account exists before and across organisations, so no `org_id`.
* RLS scoped `TO identity_app` with `USING (true)`, as in 0001: the service must see every link to resolve a sign-in;
  no other role has a policy. The service may insert and delete links (unlinking is an operator action), not
  rewrite them: a link pointing at another account is a new link.
* The audit action list gains `oauth_signin`, `oauth_linked` and `admin_bootstrapped`.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
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
"""

# Data-destroying by nature: every OAuth link goes (accounts keep signing in by email), and audit rows with the new
# actions are removed so the narrower constraint can be restored.
DOWNGRADE_SQL = """
DROP TABLE identity.oauth_accounts;
ALTER TABLE identity.audit DROP CONSTRAINT audit_action_check;
DELETE FROM identity.audit WHERE action IN ('oauth_signin', 'oauth_linked', 'admin_bootstrapped');
ALTER TABLE identity.audit ADD CONSTRAINT audit_action_check CHECK (action IN (
  'signin', 'signin_failed', 'refresh', 'logout', 'revoke', 'reuse_detected',
  'test_signin', 'status_change', 'password_set', 'user_created'));
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
