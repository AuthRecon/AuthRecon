"""add tech fingerprint storage to runs

Revision ID: 0004_add_tech_fingerprint
Revises: 0003_add_artifact_encryption
Create Date: 2024-10-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "0004_add_tech_fingerprint"
down_revision = "0003_add_artifact_encryption"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column(
            "tech_fingerprint",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("runs", "tech_fingerprint")
