"""api keys: scope ("full" or "read")

A read-only key can list and inspect, but every write (submit, cancel, rerun,
verify, settings) is refused, so an AI client given one cannot start anything.

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-16
"""
import sqlalchemy as sa
from alembic import op

revision = '0027_api_key_scope'
down_revision = '0026_credential_allowed_domains'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("scope", sa.String(20), nullable=False, server_default="full"))


def downgrade() -> None:
    op.drop_column("api_keys", "scope")
