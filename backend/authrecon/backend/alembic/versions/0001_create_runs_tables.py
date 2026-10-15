"""create runs artifacts timeline tables

Revision ID: 0001_create_runs
Revises: 
Create Date: 2025-09-27 14:30:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

# revision identifiers, used by Alembic.
revision = "0001_create_runs"
down_revision = None
branch_labels = None
depends_on = None


run_status_enum = postgresql.ENUM(
    "queued",
    "running",
    "succeeded",
    "failed",
    name="run_status",
)
run_status_enum_no_create = postgresql.ENUM(
    "queued",
    "running",
    "succeeded",
    "failed",
    name="run_status",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    run_status_enum.create(bind, checkfirst=True)

    op.create_table(
        "runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("status", run_status_enum_no_create, nullable=False),
        sa.Column("auth_type", sa.String(length=100), nullable=True),
        sa.Column("operator", sa.String(length=100), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("final_url", sa.Text(), nullable=True),
        sa.Column("pattern", sa.Text(), nullable=True),
        sa.Column("llm_pattern", sa.Text(), nullable=True),
        sa.Column("session_cookies", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("options", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )

    op.create_index("ix_runs_submitted_at", "runs", ["submitted_at"])

    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(length=40), primary_key=True),
        sa.Column("run_id", sa.String(length=36), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("type", sa.String(length=50), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("storage_path", sa.Text(), nullable=True),
        sa.Column("download_url", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_artifacts_run_id", "artifacts", ["run_id"])
    op.create_index("ix_artifacts_created_at", "artifacts", ["created_at"])

    op.create_table(
        "timeline_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(length=36), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
    )

    op.create_index("ix_timeline_events_run_id", "timeline_events", ["run_id"])
    op.create_index("ix_timeline_events_occurred_at", "timeline_events", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_timeline_events_occurred_at", table_name="timeline_events")
    op.drop_index("ix_timeline_events_run_id", table_name="timeline_events")
    op.drop_table("timeline_events")

    op.drop_index("ix_artifacts_created_at", table_name="artifacts")
    op.drop_index("ix_artifacts_run_id", table_name="artifacts")
    op.drop_table("artifacts")

    op.drop_index("ix_runs_submitted_at", table_name="runs")
    op.drop_table("runs")

    bind = op.get_bind()
    run_status_enum.drop(bind, checkfirst=True)
