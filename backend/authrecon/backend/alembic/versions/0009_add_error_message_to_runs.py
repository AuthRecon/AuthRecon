"""add error_message to runs

Revision ID: 0009
Revises: 0008
Create Date: 2025-11-24

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0009_add_error_message_to_runs'
down_revision = '0008_add_role_slug_to_artifacts'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add error_message column to runs table for storing unsupported auth type messages."""
    op.add_column(
        'runs',
        sa.Column('error_message', sa.Text(), nullable=True)
    )


def downgrade() -> None:
    """Remove error_message column from runs table."""
    op.drop_column('runs', 'error_message')
