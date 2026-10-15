"""Unit-test setup: the app config fails closed without strong secrets, so
give the test process random ones before anything imports app.core.config."""
from __future__ import annotations

import os
import secrets
import sys
import tempfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

for _name in ("SECRET_KEY", "JWT_SECRET_KEY", "PORTAL_API_SECRET"):
    os.environ.setdefault(_name, secrets.token_hex(32))
os.environ.setdefault("ARTIFACTS_DIR", tempfile.mkdtemp(prefix="authrecon-test-artifacts-"))

# Importing any ``app.*`` module runs app/__init__ -> app.main, which mounts the
# noVNC assets at /opt/novnc (present only in the worker image). Skip that
# directory check in unit tests.
import starlette.staticfiles as _staticfiles  # noqa: E402

_original_static_init = _staticfiles.StaticFiles.__init__


def _static_init_without_dir_check(self, *args, **kwargs):
    kwargs["check_dir"] = False
    _original_static_init(self, *args, **kwargs)


_staticfiles.StaticFiles.__init__ = _static_init_without_dir_check


# --- shared fixtures for artifact encryption tests ----------------------------
import pytest  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB  # noqa: E402
from sqlalchemy.ext.compiler import compiles  # noqa: E402


@compiles(JSONB, "sqlite")
def _jsonb_as_json_on_sqlite(_type, _compiler, **_kw):  # models use Postgres JSONB
    return "JSON"


@pytest.fixture()
def db_session():
    """Real models on an in-memory SQLite DB."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import models  # noqa: F401  (register tables)
    from app.db.base import Base

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = factory()
    session.factory = factory
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def artifact_storage(tmp_path, monkeypatch, db_session):
    """An ArtifactStorage rooted in tmp_path whose fallback resolver uses the test DB."""
    from app.models import Run
    from app.services import storage as storage_module
    from app.services.artifact_crypto import write_key_for_run

    def resolver(run_id):
        return write_key_for_run(db_session, db_session.get(Run, run_id))

    store = storage_module.ArtifactStorage(tmp_path / "artifacts", key_resolver=resolver)
    monkeypatch.setattr(storage_module, "get_artifact_storage", lambda: store)
    import app.api.artifacts as artifacts_api  # imported the name directly

    monkeypatch.setattr(artifacts_api, "get_artifact_storage", lambda: store)
    return store


@pytest.fixture()
def make_run(db_session):
    """Create a run, optionally owned by a fresh profile (with an artifact key)."""
    import uuid
    from datetime import datetime, timezone

    from app.models import Run
    from app.services.profiles import sync_portal_profile

    def _make(owned: bool = True, portal_user_id: str | None = None):
        profile = None
        if owned:
            profile = sync_portal_profile(db_session, portal_user_id or str(uuid.uuid4()))
        run = Run(
            id=str(uuid.uuid4()),
            target_url="https://target.invalid/login",
            status="succeeded",
            submitted_at=datetime.now(timezone.utc),
            submitted_by_profile_id=profile.id if profile else None,
            options={},
        )
        db_session.add(run)
        db_session.commit()
        return run, profile

    return _make
