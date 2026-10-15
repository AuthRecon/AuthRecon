"""add security context storage to runs

Revision ID: 0011_add_security_context
Revises: 0010_migrate_users_to_profiles
Create Date: 2025-11-29 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "0011_add_security_context"
down_revision = "0010_migrate_users_to_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column(
            "security_context",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("runs", "security_context")
