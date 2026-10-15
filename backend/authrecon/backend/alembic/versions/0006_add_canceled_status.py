"""Add a canceled state to scanner status enum.

Revision ID: 0006_add_canceled_status
Revises: 0005_add_scanner_tables
Create Date: 2025-11-16 04:35:00.000000
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "0006_add_canceled_status"
down_revision = "0005_add_scanner_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE scanner_status ADD VALUE IF NOT EXISTS 'canceled'")


def downgrade() -> None:
    # PostgreSQL cannot drop enum labels safely without recreating the type,
    # so we leave the value in place during downgrade.
    pass
