"""stored credentials: allowed_domains

Bind each stored credential to the hosts it may be used on, so a run (or an AI
client) cannot send it to another site. Existing credentials start unbound and
are bound to the host of the next run that uses them.

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-16
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = '0026_credential_allowed_domains'
down_revision = '0025_strip_url_credentials'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "stored_credentials",
        sa.Column("allowed_domains", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("stored_credentials", "allowed_domains")
