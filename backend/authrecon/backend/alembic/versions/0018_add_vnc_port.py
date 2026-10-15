"""add vnc_port to runs for manual recording sessions

Revision ID: 0018
Revises: 0017
Create Date: 2026-01-09

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0018_add_vnc_port'
down_revision = '0017_add_manual_recording_status'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add vnc_port column to runs table for tracking VNC port per manual session."""
    op.add_column(
        'runs',
        sa.Column('vnc_port', sa.Integer(), nullable=True)
    )


def downgrade() -> None:
    """Remove vnc_port column from runs table."""
    op.drop_column('runs', 'vnc_port')
