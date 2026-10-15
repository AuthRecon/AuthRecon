"""scrub known passwords from response bodies of existing HARs

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-02

Data-only. Installs that already ran 0020 have HARs that are encrypted and
request-masked, but a password echoed in a response body (e.g. a login page
that prints it, or an error page) was not scrubbed. This re-runs the
idempotent artifact migration, whose second pass decrypts each HAR, replaces
the run's known passwords (plain, URL-, HTML-entity-, JSON- and base64-encoded
forms) in response bodies, and re-encrypts only HARs that changed.

Same guarantees as 0020: own DB session, Postgres advisory lock (and the whole
upgrade runs under app.db.migrate's lock), per-file failures logged, never
fails the upgrade. Re-run by hand with `python -m app.services.artifact_migration`.
"""
import logging

import sqlalchemy as sa
from alembic import op

revision = '0021_scrub_har_response_bodies'
down_revision = '0020_encrypt_artifacts_at_rest'
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
        logger.info("HAR response-body scrub: %s", report.summary())
        if report.failed:
            logger.warning(
                "%d artifact(s) not processed; re-run `python -m app.services.artifact_migration`",
                report.failed,
            )
    except Exception:
        logger.exception(
            "HAR response-body scrub did not complete. "
            "Re-run `python -m app.services.artifact_migration`."
        )


def downgrade() -> None:
    # Irreversible by design: scrubbed passwords are not restored.
    pass
