"""add auth and credential tables

Revision ID: 0002_add_auth_models
Revises: 0001_create_runs
Create Date: 2025-10-21 17:05:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0002_add_auth_models"
down_revision = "0001_create_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.sql.expression.true()),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.sql.expression.false()),
        sa.Column("auth_provider", sa.String(length=50), nullable=False, server_default="local"),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.add_column(
        "runs",
        sa.Column(
            "submitted_by_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_runs_submitted_by_user_id", "runs", ["submitted_by_user_id"])

    op.create_table(
        "stored_credentials",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("auth_type", sa.String(length=100), nullable=False, server_default="generic"),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("additional_fields", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_archived", sa.Boolean(), nullable=False, server_default=sa.sql.expression.false()),
        sa.Column("owner_user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_stored_credentials_owner_user_id", "stored_credentials", ["owner_user_id"])
    op.create_index("ix_stored_credentials_is_archived", "stored_credentials", ["is_archived"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(length=40), primary_key=True),
        sa.Column("actor_user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("credential_id", sa.String(length=36), sa.ForeignKey("stored_credentials.id", ondelete="SET NULL"), nullable=True),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("entity_id", sa.String(length=50), nullable=True),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_log_actor_user_id", "audit_log", ["actor_user_id"])
    op.create_index("ix_audit_log_credential_id", "audit_log", ["credential_id"])
    op.create_index("ix_audit_log_occurred_at", "audit_log", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_runs_submitted_by_user_id", table_name="runs")
    op.drop_column("runs", "submitted_by_user_id")

    op.drop_index("ix_audit_log_occurred_at", table_name="audit_log")
    op.drop_index("ix_audit_log_credential_id", table_name="audit_log")
    op.drop_index("ix_audit_log_actor_user_id", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_index("ix_stored_credentials_is_archived", table_name="stored_credentials")
    op.drop_index("ix_stored_credentials_owner_user_id", table_name="stored_credentials")
    op.drop_table("stored_credentials")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
