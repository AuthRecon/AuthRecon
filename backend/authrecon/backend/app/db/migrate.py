"""Run ``alembic upgrade head`` under a Postgres advisory lock.

authrecon-api and authrecon-worker both migrate at startup. Without a lock they
race on Alembic's version stamp ("expected to match one row when updating
'0019…' to '0020…'; 0 found") and one container exits. With it, the second
container waits, then finds the DB already at head and does nothing.

Usage (docker-entrypoint.sh):  python -m app.db.migrate
"""
from __future__ import annotations

import logging
import os
import sys
import time
import traceback
from pathlib import Path

from sqlalchemy import create_engine, text

logger = logging.getLogger("authrecon.migrate")

# Distinct from the artifact data migration's own lock (0x41524543), which is
# taken inside revision 0020 on a separate connection.
MIGRATION_LOCK_ID = 0x41524D47  # "ARMG"
DEFAULT_WAIT_SECONDS = 900
POLL_SECONDS = 2.0


def _alembic_config():
    from alembic.config import Config

    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "alembic"))
    return config


def _run_upgrade() -> None:
    from alembic import command

    command.upgrade(_alembic_config(), "head")


def acquire_lock(conn, *, lock_id: int, wait_seconds: float, poll: float = POLL_SECONDS, sleep=time.sleep) -> bool:
    """Poll pg_try_advisory_lock so a stuck holder can't hang startup forever."""
    deadline = time.monotonic() + wait_seconds
    announced = False
    while True:
        if conn.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}).scalar():
            return True
        if time.monotonic() >= deadline:
            return False
        if not announced:
            logger.info("Another container is running migrations; waiting for it to finish")
            announced = True
        sleep(poll)


def upgrade_with_lock(
    database_url: str,
    *,
    run_upgrade=_run_upgrade,
    wait_seconds: float = DEFAULT_WAIT_SECONDS,
    engine_factory=create_engine,
) -> None:
    engine = engine_factory(database_url, pool_pre_ping=True)
    try:
        if engine.dialect.name != "postgresql":
            run_upgrade()
            return
        # The lock lives on this dedicated connection for the whole upgrade;
        # Alembic uses its own connection.
        with engine.connect() as conn:
            conn = conn.execution_options(isolation_level="AUTOCOMMIT")
            if not acquire_lock(conn, lock_id=MIGRATION_LOCK_ID, wait_seconds=wait_seconds):
                raise TimeoutError(
                    f"Timed out after {wait_seconds:.0f}s waiting for the migration lock"
                )
            try:
                run_upgrade()
            finally:
                conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": MIGRATION_LOCK_ID})
    finally:
        engine.dispose()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    from app.core.config import get_settings

    wait = float(os.getenv("MIGRATION_LOCK_WAIT_SECONDS", DEFAULT_WAIT_SECONDS))
    # Print the outcome directly: Alembic's env.py runs logging.fileConfig(),
    # which disables loggers created before it (including this module's).
    try:
        upgrade_with_lock(str(get_settings().database_url), wait_seconds=wait)
    except Exception:
        traceback.print_exc()
        print("Database migration failed", file=sys.stderr, flush=True)
        return 1
    print("Database is at the latest revision", flush=True)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
