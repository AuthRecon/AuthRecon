"""add flow_summary to runs

Revision ID: 0015
Revises: 0014
Create Date: 2025-12-22

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0015_add_flow_summary_to_runs'
down_revision = '0014_add_api_keys'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add flow_summary column to runs table for storing human-readable auth flow narratives."""
    op.add_column(
        'runs',
        sa.Column('flow_summary', sa.Text(), nullable=True)
    )


def downgrade() -> None:
    """Remove flow_summary column from runs table."""
    op.drop_column('runs', 'flow_summary')
