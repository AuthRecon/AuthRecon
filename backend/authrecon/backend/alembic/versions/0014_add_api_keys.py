"""add api keys for CLI authentication

Revision ID: 0014_add_api_keys
Revises: 0013_add_tenant_playbooks
Create Date: 2025-12-14 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0014_add_api_keys"
down_revision = "0013_add_tenant_playbooks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Create api_keys table and add api_access_enabled to profiles.

    API keys provide CLI/programmatic authentication as an alternative to JWT tokens.
    Admin users can grant API access to specific profiles via api_access_enabled flag.
    """
    # Add api_access_enabled column to profiles
    op.add_column(
        "authrecon_profiles",
        sa.Column(
            "api_access_enabled",
            sa.Boolean(),
            nullable=False,
            server_default="false",
            comment="Admin-controlled flag: allow this user to generate API keys"
        )
    )

    # Create api_keys table
    op.create_table(
        "api_keys",
        # Primary key
        sa.Column("id", sa.String(36), primary_key=True),

        # Owner profile (foreign key with CASCADE delete)
        sa.Column(
            "profile_id",
            sa.String(36),
            sa.ForeignKey("authrecon_profiles.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            comment="Profile that owns this API key"
        ),

        # Key identification
        sa.Column(
            "name",
            sa.String(150),
            nullable=False,
            comment="User-provided name (e.g., 'CI/CD Pipeline', 'Dev Laptop')"
        ),

        sa.Column(
            "key_hash",
            sa.Text(),
            nullable=False,
            unique=True,
            comment="bcrypt hash of the API key (never store plaintext)"
        ),

        sa.Column(
            "prefix",
            sa.String(20),
            nullable=False,
            comment="Display prefix for UI (e.g., 'ak_...xJ7k')"
        ),

        # Lifecycle management
        sa.Column(
            "is_revoked",
            sa.Boolean(),
            nullable=False,
            server_default="false",
            comment="True if key has been revoked"
        ),

        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="When the key was revoked"
        ),

        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Optional expiration time for the key"
        ),

        # Usage tracking
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            comment="When the key was created"
        ),

        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Last successful authentication with this key"
        ),

        # Indexes for efficient lookup
        sa.Index("idx_api_key_hash", "key_hash"),
        sa.Index("idx_api_key_profile_revoked", "profile_id", "is_revoked"),
        sa.Index("idx_api_key_expires", "expires_at"),
    )


def downgrade() -> None:
    """Drop api_keys table and remove api_access_enabled from profiles."""
    op.drop_table("api_keys")
    op.drop_column("authrecon_profiles", "api_access_enabled")
