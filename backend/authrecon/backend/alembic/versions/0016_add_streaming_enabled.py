"""add streaming_enabled to runs

Revision ID: 0016
Revises: 0015
Create Date: 2026-01-08

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0016_add_streaming_enabled'
down_revision = '0015_add_flow_summary_to_runs'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add streaming_enabled column to runs table for VNC browser streaming feature."""
    op.add_column(
        'runs',
        sa.Column('streaming_enabled', sa.Boolean(), nullable=False, server_default='false')
    )


def downgrade() -> None:
    """Remove streaming_enabled column from runs table."""
    op.drop_column('runs', 'streaming_enabled')
