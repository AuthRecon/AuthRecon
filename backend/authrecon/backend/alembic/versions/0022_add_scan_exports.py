"""add scan_exports table for the WAS scan export analyzer

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-02
"""
from alembic import op
import sqlalchemy as sa

revision = '0022_add_scan_exports'
down_revision = '0021_scrub_har_response_bodies'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'scan_exports',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('owner_profile_id', sa.String(length=36),
                  sa.ForeignKey('authrecon_profiles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='uploaded'),
        sa.Column('summary', sa.JSON(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('parsed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_scan_exports_owner_profile_id', 'scan_exports', ['owner_profile_id'])
    op.create_index('ix_scan_exports_created_at', 'scan_exports', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_scan_exports_created_at', table_name='scan_exports')
    op.drop_index('ix_scan_exports_owner_profile_id', table_name='scan_exports')
    op.drop_table('scan_exports')
