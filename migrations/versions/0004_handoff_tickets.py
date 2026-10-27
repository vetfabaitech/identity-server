"""SSO hand-off tickets: short-lived, single-use, bound to a user, a session and a destination service.

Revision ID: 0004
Revises: 0003

* `ticket_hash` is the SHA-256 of a 256-bit random ticket (never stored raw, like refresh tokens). `consumed_at` is set
  by one atomic UPDATE, so a ticket redeems at most once however many requests race for it.
* `family_id` is the central session (the refresh-token family) the ticket was issued from; a ticket stops working when
  that session is revoked, the user is suspended, or it expires.
* The audit action list gains the three hand-off actions.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
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
"""

# Data-destroying by nature: outstanding tickets go, and audit rows with the hand-off actions are removed so the
# narrower constraint can be restored.
DOWNGRADE_SQL = """
DROP TABLE identity.handoff_tickets;
ALTER TABLE identity.audit DROP CONSTRAINT audit_action_check;
DELETE FROM identity.audit WHERE action IN ('handoff_issued', 'handoff_redeemed', 'handoff_rejected');
ALTER TABLE identity.audit ADD CONSTRAINT audit_action_check CHECK (action IN (
  'signin', 'signin_failed', 'refresh', 'logout', 'revoke', 'reuse_detected',
  'test_signin', 'status_change', 'password_set', 'user_created',
  'oauth_signin', 'oauth_linked', 'admin_bootstrapped'));
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
