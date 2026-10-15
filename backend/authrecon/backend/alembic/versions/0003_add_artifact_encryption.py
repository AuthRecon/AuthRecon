"""add per-user artifact encryption support

Revision ID: 0003_add_artifact_encryption
Revises: 0002_add_auth_models
Create Date: 2025-10-22 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0003_add_artifact_encryption"
down_revision = "0002_add_auth_models"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("artifact_key_encrypted", sa.Text(), nullable=True))

    op.add_column(
        "artifacts",
        sa.Column(
            "is_encrypted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.sql.expression.false(),
        ),
    )
    op.add_column(
        "artifacts",
        sa.Column("encryption_owner_user_id", sa.String(length=36), nullable=True),
    )
    op.create_foreign_key(
        "fk_artifacts_encryption_owner_user_id_users",
        "artifacts",
        "users",
        ["encryption_owner_user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_artifacts_encryption_owner_user_id_users",
        "artifacts",
        type_="foreignkey",
    )
    op.drop_column("artifacts", "encryption_owner_user_id")
    op.drop_column("artifacts", "is_encrypted")

    op.drop_column("users", "artifact_key_encrypted")
