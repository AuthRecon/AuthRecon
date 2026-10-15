"""profile display_name for API-key attribution; unify the manual auth_type

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-02
"""
from alembic import op
import sqlalchemy as sa

revision = '0024_profile_display_name'
down_revision = '0023_mcp_settings'
branch_labels = None
depends_on = None

BACKFILL_DISPLAY_NAME = """
UPDATE authrecon_profiles p SET display_name = (
    SELECT r.operator FROM runs r
    WHERE r.submitted_by_profile_id = p.id
      AND r.operator IS NOT NULL AND r.operator NOT IN ('api_key_user', 'unknown', 'unknown user')
    ORDER BY r.submitted_at DESC LIMIT 1
) WHERE p.display_name IS NULL
"""


def upgrade() -> None:
    op.add_column('authrecon_profiles', sa.Column('display_name', sa.String(length=150), nullable=True))
    # Backfill from each profile's most recent web-submitted run (its operator
    # is the portal username); later logins keep it current.
    op.execute(BACKFILL_DISPLAY_NAME)
    # Manual sessions were stored as "manual" at submit and only renamed to
    # "manual_recording" when the session completed normally.
    op.execute("UPDATE runs SET auth_type = 'manual_recording' WHERE auth_type = 'manual'")
    op.execute("UPDATE tenant_playbooks SET auth_type = 'form_based' "
               "WHERE auth_type IN ('form_auth', 'form_post', 'form_login', 'form')")


def downgrade() -> None:
    op.drop_column('authrecon_profiles', 'display_name')
