"""add session_cookies_enc column for encrypted cookie storage

Revision ID: 0019
Revises: 0018
Create Date: 2026-05-30

New runs write captured session cookies to session_cookies_enc (Fernet,
per-profile key) and leave session_cookies empty.  Old rows keep their
plaintext data in session_cookies; decrypt_session_cookies() falls back
to that column when enc is absent.
"""
from alembic import op
import sqlalchemy as sa


revision = '0019_encrypt_session_cookies'
down_revision = '0018_add_vnc_port'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('runs', sa.Column('session_cookies_enc', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('runs', 'session_cookies_enc')
