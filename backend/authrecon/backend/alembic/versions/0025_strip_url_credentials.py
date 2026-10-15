"""strip user:password@ from stored run URLs

Basic-auth runs stored the browser's current URL, which still carried the
credentials (https://user:pass@host/). Remove them from runs.final_url and
artifact descriptions. New runs strip them before saving (app/core/urls.py).

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-14
"""
from alembic import op

revision = '0025_strip_url_credentials'
down_revision = '0024_profile_display_name'
branch_labels = None
depends_on = None

# scheme://<userinfo>@host...  ->  scheme://host...
_USERINFO = r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/?#@\s]+@"


def upgrade() -> None:
    op.execute(
        f"UPDATE runs SET final_url = regexp_replace(final_url, '{_USERINFO}', '\\1', 'g') "
        f"WHERE final_url ~ '{_USERINFO}'"
    )
    op.execute(
        f"UPDATE artifacts SET description = regexp_replace(description, '{_USERINFO}', '\\1', 'g') "
        f"WHERE description ~ '{_USERINFO}'"
    )


def downgrade() -> None:
    pass  # the removed credentials are not restored
