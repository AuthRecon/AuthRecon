"""app_settings table (MCP on/off) and per-key MCP last-connected time

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-02
"""
from alembic import op
import sqlalchemy as sa

revision = '0023_mcp_settings'
down_revision = '0022_add_scan_exports'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'app_settings',
        sa.Column('key', sa.String(length=100), primary_key=True),
        sa.Column('value', sa.JSON(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column('api_keys', sa.Column('last_mcp_used_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('api_keys', 'last_mcp_used_at')
    op.drop_table('app_settings')
