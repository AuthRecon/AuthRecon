"""Expand scanner_runs.template_set length to support full scan list.

Revision ID: 0012_expand_template_set_length
Revises: 0011_add_security_context
Create Date: 2025-12-06 18:05:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0012_expand_template_set_length"
down_revision = "0011_add_security_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "scanner_runs",
        "template_set",
        existing_type=sa.String(length=100),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    # Warning: downgrading may truncate values longer than 100 chars.
    op.alter_column(
        "scanner_runs",
        "template_set",
        existing_type=sa.Text(),
        type_=sa.String(length=100),
        existing_nullable=True,
    )
