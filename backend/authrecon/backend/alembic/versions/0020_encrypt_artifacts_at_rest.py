"""encrypt existing artifacts at rest; mask passwords in existing HARs

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-01

Data-only migration (no schema change). Rewrites every stored artifact into the
versioned ``ARENC:<key-id>:<token>`` format (per-user Fernet key; the master key
only for runs with no owner) and masks password values in HARs first.

It is idempotent and never blocks startup: per-file failures are logged, and
anything left over is still readable (legacy formats) and can be finished with
``python -m app.services.artifact_migration``. It uses its own DB session so a
profile key is committed before any file depends on it.
"""
import logging

import sqlalchemy as sa
from alembic import op

revision = '0020_encrypt_artifacts_at_rest'
down_revision = '0019_encrypt_session_cookies'
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")


def _no_artifacts_yet() -> bool:
    try:
        return op.get_bind().execute(sa.text("SELECT 1 FROM artifacts LIMIT 1")).first() is None
    except Exception:
        return False  # can't tell (e.g. called outside Alembic): run the pass


def upgrade() -> None:
    # The data pass uses its own session, which can't see tables created
    # earlier in this (still uncommitted) Alembic transaction. On a fresh
    # install there are no artifacts yet, so there is nothing to do.
    if _no_artifacts_yet():
        logger.info("No artifacts yet; skipping the artifact data migration")
        return
    try:
        from app.services.artifact_migration import run_migration

        report = run_migration()
        logger.info("Artifact encryption: %s", report.summary())
        if report.failed:
            logger.warning(
                "%d artifact(s) not migrated; re-run `python -m app.services.artifact_migration`",
                report.failed,
            )
    except Exception:
        logger.exception(
            "Artifact encryption migration did not complete; legacy artifacts stay readable. "
            "Re-run `python -m app.services.artifact_migration`."
        )


def downgrade() -> None:
    # Irreversible by design: decrypting artifacts back to plaintext on disk
    # (or un-masking HAR passwords) is not supported.
    pass
