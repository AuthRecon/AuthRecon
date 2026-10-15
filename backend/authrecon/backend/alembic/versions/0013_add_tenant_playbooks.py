"""add tenant playbooks for historical learning

Revision ID: 0013_add_tenant_playbooks
Revises: 0012_expand_template_set_length
Create Date: 2025-12-14 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "0013_add_tenant_playbooks"
down_revision = "0012_expand_template_set_length"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Create tenant_playbooks table for Phase 4 historical learning.

    This table stores successful authentication patterns that can be reused
    for deterministic logins instead of heuristic detection.
    """
    op.create_table(
        "tenant_playbooks",
        # Primary key
        sa.Column("id", sa.String(36), primary_key=True),

        # Tenant/domain identification
        sa.Column("domain", sa.String(255), nullable=False, index=True),
        sa.Column("profile_id", sa.String(36), nullable=True, index=True),  # Multi-tenant isolation

        # Authentication pattern
        sa.Column("auth_type", sa.String(100), nullable=False),

        # Learned selectors (from successful runs)
        sa.Column(
            "selectors",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            comment="Exact selectors for username, password, submit fields"
        ),

        # Endpoints
        sa.Column(
            "endpoints",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Primary auth endpoint and related URLs"
        ),

        # Confidence and validation
        sa.Column("confidence_score", sa.Integer, nullable=False, default=100),
        sa.Column("success_count", sa.Integer, nullable=False, default=1),
        sa.Column("failure_count", sa.Integer, nullable=False, default=0),

        # Metadata
        sa.Column("learned_from_run_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("last_successful_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),

        # Additional context
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Additional context: tech stack, provider hints, etc."
        ),

        # Indexes for efficient lookup
        sa.Index("idx_playbook_domain_profile", "domain", "profile_id"),
        sa.Index("idx_playbook_domain_authtype", "domain", "auth_type"),
    )


def downgrade() -> None:
    """Drop tenant_playbooks table."""
    op.drop_table("tenant_playbooks")
