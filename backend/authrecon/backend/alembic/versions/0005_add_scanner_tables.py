"""Add shared asset + scanner run tables.

Revision ID: 0005_add_scanner_tables
Revises: 0004_add_tech_fingerprint
Create Date: 2025-11-12 18:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "0005_add_scanner_tables"
down_revision = "0004_add_tech_fingerprint"
branch_labels = None
depends_on = None


scanner_status_enum = postgresql.ENUM(
    "queued",
    "running",
    "completed",
    "failed",
    name="scanner_status",
)
scanner_status_column_type = postgresql.ENUM(
    "queued",
    "running",
    "completed",
    "failed",
    name="scanner_status",
    create_type=False,
)


def upgrade() -> None:
    scanner_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column(
            "labels",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "extra_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "scanner_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("engine", sa.String(length=50), nullable=False, server_default="nuclei"),
        sa.Column("template_set", sa.String(length=100), nullable=True),
        sa.Column("status", scanner_status_column_type, nullable=False, server_default="queued"),
        sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("auth_run_id", sa.String(length=36), sa.ForeignKey("runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column(
            "triggered_by_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "extra_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_index(op.f("ix_scanner_runs_triggered_by_user_id"), "scanner_runs", ["triggered_by_user_id"], unique=False)

    op.create_table(
        "scanner_findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scanner_run_id", sa.String(length=36), sa.ForeignKey("scanner_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("cwe", sa.String(length=50), nullable=True),
        sa.Column("cve", sa.String(length=50), nullable=True),
        sa.Column("cvss", sa.Numeric(4, 2), nullable=True),
        sa.Column(
            "references",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index(op.f("ix_scanner_findings_scanner_run_id"), "scanner_findings", ["scanner_run_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scanner_findings_scanner_run_id"), table_name="scanner_findings")
    op.drop_table("scanner_findings")

    op.drop_index(op.f("ix_scanner_runs_triggered_by_user_id"), table_name="scanner_runs")
    op.drop_table("scanner_runs")

    op.drop_table("assets")

    scanner_status_enum.drop(op.get_bind(), checkfirst=True)
