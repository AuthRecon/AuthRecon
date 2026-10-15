"""One-time migration: encrypt existing artifacts at rest and mask passwords in existing HARs.

Two idempotent passes, both under one Postgres advisory lock:
1. ``migrate_artifacts``: encrypt anything not yet in ``ARENC:`` format (HARs
   are masked first: requests and response bodies, with the run's passwords).
2. ``scrub_existing_hars``: decrypt already-encrypted HARs, scrub the run's
   passwords from response bodies, and re-encrypt only if something changed.

Runs automatically via Alembic revisions 0020 and 0021; can also be run by
hand inside the authrecon-api container:

    python -m app.services.artifact_migration            # migrate
    python -m app.services.artifact_migration --dry-run  # report only

Per-file failures are logged and counted, never fatal. Logs name artifacts by
id only, never their contents.
"""
from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass, field

from sqlalchemy import select, text

logger = logging.getLogger(__name__)

_ADVISORY_LOCK_ID = 0x41524543  # "AREC": serialize api/worker containers running upgrades at once


@dataclass
class MigrationReport:
    encrypted: int = 0
    already_encrypted: int = 0
    har_masked: int = 0
    har_scrubbed: int = 0  # encrypted HARs whose bodies still held a password, now rewritten
    har_clean: int = 0  # encrypted HARs checked and already clean (left byte-identical)
    missing_file: int = 0
    failed: int = 0
    failed_ids: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"encrypted={self.encrypted} already_encrypted={self.already_encrypted} "
            f"har_masked={self.har_masked} har_scrubbed={self.har_scrubbed} har_clean={self.har_clean} "
            f"missing_file={self.missing_file} failed={self.failed}"
        )


def _provision_missing_profile_keys(db) -> int:
    """Give every profile an artifact key up front, under a row lock, and commit.

    Doing this before any file is rewritten means no file can end up encrypted
    with a key that a rolled-back or concurrent transaction never persisted.
    """
    from cryptography.fernet import Fernet

    from app.core.security import encrypt_with_master
    from app.models.profile import AuthReconProfile

    stmt = select(AuthReconProfile).where(AuthReconProfile.artifact_key_encrypted.is_(None))
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        stmt = stmt.with_for_update()
    count = 0
    for profile in db.scalars(stmt).all():
        profile.artifact_key_encrypted = encrypt_with_master(Fernet.generate_key())
        count += 1
    db.commit()
    return count


def migrate_artifacts(db, storage, *, dry_run: bool = False) -> MigrationReport:
    from app.models import Artifact
    from app.services.artifact_crypto import (
        decode_artifact_payload,
        is_wrapped,
        scrub_har_for_run,
        write_key_for_run,
        _is_har,
    )

    report = MigrationReport()
    if not dry_run:
        provisioned = _provision_missing_profile_keys(db)
        if provisioned:
            logger.info("Provisioned artifact keys for %d profile(s)", provisioned)

    artifact_ids = db.scalars(select(Artifact.id).where(Artifact.storage_path.is_not(None))).all()
    for artifact_id in artifact_ids:
        artifact = db.get(Artifact, artifact_id)
        if artifact is None:
            continue
        try:
            path = storage.resolve(artifact.storage_path)
        except (FileNotFoundError, ValueError):
            report.missing_file += 1
            continue
        try:
            data = path.read_bytes()
            if is_wrapped(data):
                report.already_encrypted += 1
                if not artifact.is_encrypted and not dry_run:
                    artifact.is_encrypted = True
                    db.commit()
                continue

            run = artifact.run
            # Legacy raw-Fernet .side -> plaintext; legacy plaintext HAR -> masked.
            plaintext = decode_artifact_payload(data, db=db, run=run, artifact=artifact)
            if _is_har(artifact):
                # Requests + response bodies, with the run's known passwords.
                plaintext = scrub_har_for_run(plaintext, db=db, run=run)
                report.har_masked += 1

            if dry_run:
                report.encrypted += 1
                continue

            storage.bind_run_key(run.id, write_key_for_run(db, run))
            name = artifact.name or path.name
            if _is_har(artifact) and not name.lower().endswith(".har"):
                name = f"{name}.har"
            payload = storage.prepare_bytes(run.id, name, plaintext)
            storage.replace_bytes(artifact.storage_path, payload)
            artifact.is_encrypted = True
            db.commit()
            report.encrypted += 1
        except Exception:
            db.rollback()
            report.failed += 1
            report.failed_ids.append(artifact_id)
            logger.warning("Artifact %s could not be migrated", artifact_id, exc_info=True)
        finally:
            if artifact is not None and artifact.run_id:
                storage.release_run(artifact.run_id)
    return report


def scrub_existing_hars(db, storage, *, dry_run: bool = False, report: MigrationReport | None = None) -> MigrationReport:
    """Second pass: scrub known passwords from response bodies of already-encrypted HARs.

    Covers installs where 0020 encrypted HARs before response-body scrubbing
    existed. A HAR is rewritten only if scrubbing changes it, so re-runs are
    no-ops. Plaintext (legacy) HARs are left to ``migrate_artifacts``.
    """
    from app.models import Artifact
    from app.services.artifact_crypto import (
        cipher_resolver_for_run,
        is_wrapped,
        scrub_har_for_run,
        unwrap,
        write_key_for_run,
        _is_har,
    )

    report = report or MigrationReport()
    ids = db.scalars(select(Artifact.id).where(Artifact.storage_path.is_not(None))).all()
    for artifact_id in ids:
        artifact = db.get(Artifact, artifact_id)
        if artifact is None or not _is_har(artifact):
            continue
        try:
            path = storage.resolve(artifact.storage_path)
        except (FileNotFoundError, ValueError):
            continue  # already counted by the encryption pass
        try:
            data = path.read_bytes()
            if not is_wrapped(data):
                continue
            run = artifact.run
            plain = unwrap(data, cipher_resolver_for_run(db, run))
            scrubbed = scrub_har_for_run(plain, db=db, run=run)
            if scrubbed == plain:
                report.har_clean += 1
                continue
            report.har_scrubbed += 1
            if dry_run:
                continue
            storage.bind_run_key(run.id, write_key_for_run(db, run))
            name = artifact.name if (artifact.name or "").lower().endswith(".har") else f"{artifact.name or path.name}.har"
            storage.replace_bytes(artifact.storage_path, storage.prepare_bytes(run.id, name, scrubbed))
            db.commit()
        except Exception:
            db.rollback()
            report.failed += 1
            report.failed_ids.append(artifact_id)
            logger.warning("HAR %s could not be scrubbed", artifact_id, exc_info=True)
        finally:
            if artifact.run_id:
                storage.release_run(artifact.run_id)
    return report


def run_migration(*, dry_run: bool = False, session_factory=None, storage=None) -> MigrationReport:
    """Entry point for Alembic and the CLI; uses its own session so commits are independent."""
    if session_factory is None:
        from app.db import SessionLocal as session_factory
    if storage is None:
        from app.services.storage import get_artifact_storage

        storage = get_artifact_storage()

    db = session_factory()
    locked = False
    try:
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _ADVISORY_LOCK_ID})
            locked = True
        report = migrate_artifacts(db, storage, dry_run=dry_run)
        scrub_existing_hars(db, storage, dry_run=dry_run, report=report)
        logger.info("Artifact encryption migration%s: %s", " (dry run)" if dry_run else "", report.summary())
        return report
    finally:
        # Always end the transaction and release the lock, even after an
        # error: an aborted transaction would reject the unlock, leak this
        # connection with the lock still held, and hang the next migration
        # that asks for it (0021 runs right after 0020 in the same process).
        try:
            db.rollback()
            if locked:
                db.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _ADVISORY_LOCK_ID})
                db.commit()
        finally:
            db.close()


def main() -> None:  # pragma: no cover - thin CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="report what would change; write nothing")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    report = run_migration(dry_run=args.dry_run)
    print(report.summary())
    if report.failed_ids:
        print("failed artifact ids:", ", ".join(report.failed_ids))


if __name__ == "__main__":  # pragma: no cover
    main()
