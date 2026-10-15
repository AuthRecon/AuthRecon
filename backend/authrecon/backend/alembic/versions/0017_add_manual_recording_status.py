"""Add manual_recording status to run_status enum

Revision ID: 0017_add_manual_recording_status
Revises: 0016_add_streaming_enabled
Create Date: 2026-01-08
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "0017_add_manual_recording_status"
down_revision = "0016_add_streaming_enabled"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add manual_recording status for operator-guided authentication sessions."""
    op.execute("ALTER TYPE run_status ADD VALUE IF NOT EXISTS 'manual_recording'")


def downgrade() -> None:
    # PostgreSQL cannot drop enum labels safely without recreating the type,
    # so we leave the value in place during downgrade.
    pass
