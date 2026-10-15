"""The Alembic data migration must never block startup."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

VERSIONS = Path(__file__).resolve().parents[1] / "alembic" / "versions"
REVISIONS = {
    "0020": VERSIONS / "0020_encrypt_artifacts_at_rest.py",
    "0021": VERSIONS / "0021_scrub_har_response_bodies.py",
}


def _load(rev="0020"):
    spec = importlib.util.spec_from_file_location(f"rev_{rev}", REVISIONS[rev])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_chain():
    assert _load("0020").down_revision == "0019_encrypt_session_cookies"
    assert _load("0021").down_revision == _load("0020").revision


@pytest.mark.parametrize("rev", ["0020", "0021"])
@pytest.mark.parametrize("outcome", ["raises", "partial"])
def test_upgrade_never_raises(monkeypatch, outcome, rev):
    from app.services import artifact_migration
    from app.services.artifact_migration import MigrationReport

    def fake_run_migration(**_):
        if outcome == "raises":
            raise RuntimeError("db down")
        return MigrationReport(encrypted=2, failed=1, failed_ids=["a1"])

    monkeypatch.setattr(artifact_migration, "run_migration", fake_run_migration)
    _load(rev).upgrade()  # must not raise
