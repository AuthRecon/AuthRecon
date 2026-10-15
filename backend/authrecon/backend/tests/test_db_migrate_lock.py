"""Startup migrations run under a Postgres advisory lock so api + worker don't race."""
from __future__ import annotations

import os
import threading
import time

import pytest

from app.db import migrate


class FakeResult:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        return self.value


class FakeConn:
    def __init__(self, lock_answers):
        self.lock_answers = list(lock_answers)
        self.sql = []

    def execution_options(self, **_):
        return self

    def execute(self, stmt, params=None):
        sql = str(stmt)
        self.sql.append(sql)
        if "pg_try_advisory_lock" in sql:
            return FakeResult(self.lock_answers.pop(0))
        return FakeResult(True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeEngine:
    def __init__(self, dialect, conn=None):
        self.dialect = type("D", (), {"name": dialect})()
        self.conn = conn
        self.disposed = False

    def connect(self):
        return self.conn

    def dispose(self):
        self.disposed = True


def test_non_postgres_just_upgrades():
    calls = []
    engine = FakeEngine("sqlite")
    migrate.upgrade_with_lock("sqlite://", run_upgrade=lambda: calls.append(1), engine_factory=lambda *a, **k: engine)
    assert calls == [1] and engine.disposed


def test_lock_taken_upgrade_run_then_unlocked():
    conn = FakeConn([True])
    order = []
    migrate.upgrade_with_lock(
        "postgresql://x", run_upgrade=lambda: order.append("upgrade"),
        engine_factory=lambda *a, **k: FakeEngine("postgresql", conn),
    )
    assert "pg_try_advisory_lock" in conn.sql[0] and order == ["upgrade"] and "pg_advisory_unlock" in conn.sql[-1]


def test_unlocks_even_when_upgrade_fails():
    conn = FakeConn([True])

    def boom():
        raise RuntimeError("migration failed")

    with pytest.raises(RuntimeError):
        migrate.upgrade_with_lock("postgresql://x", run_upgrade=boom,
                                  engine_factory=lambda *a, **k: FakeEngine("postgresql", conn))
    assert "pg_advisory_unlock" in conn.sql[-1]


def test_waits_for_the_other_container():
    conn = FakeConn([False, False, True])
    sleeps = []
    assert migrate.acquire_lock(conn, lock_id=1, wait_seconds=60, poll=0.1, sleep=sleeps.append)
    assert sleeps == [0.1, 0.1]


def test_times_out_instead_of_hanging():
    conn = FakeConn([False] * 1000)
    upgraded = []
    with pytest.raises(TimeoutError):
        migrate.upgrade_with_lock("postgresql://x", run_upgrade=lambda: upgraded.append(1), wait_seconds=0,
                                  engine_factory=lambda *a, **k: FakeEngine("postgresql", conn))
    assert upgraded == []


def test_distinct_from_the_artifact_data_migration_lock():
    from app.services.artifact_migration import _ADVISORY_LOCK_ID

    assert migrate.MIGRATION_LOCK_ID != _ADVISORY_LOCK_ID


# --- real Postgres (opt-in: set AUTHRECON_TEST_PG_URL) ------------------------

PG_URL = os.getenv("AUTHRECON_TEST_PG_URL")


@pytest.mark.skipif(not PG_URL, reason="set AUTHRECON_TEST_PG_URL to run against a real Postgres")
def test_concurrent_callers_are_serialized_on_real_postgres():
    active = []
    overlaps = []
    lock = threading.Lock()

    def fake_upgrade():
        with lock:
            active.append(1)
            if len(active) > 1:
                overlaps.append(1)
        time.sleep(0.5)
        with lock:
            active.pop()

    errors = []

    def worker():
        try:
            migrate.upgrade_with_lock(PG_URL, run_upgrade=fake_upgrade, wait_seconds=30)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and not overlaps
    assert time.monotonic() - started >= 1.4  # three 0.5s upgrades ran one after another


def test_artifact_migration_releases_its_lock_after_an_error(monkeypatch):
    """A failure inside the data pass used to leave the transaction aborted, so
    the unlock was rejected and the connection leaked holding the lock; the
    next revision (0021) then waited on it forever. Fresh installs hung."""
    import pytest

    import app.services.artifact_migration as am

    calls = []

    class _Session:
        class bind:
            class dialect:
                name = "postgresql"

        def execute(self, stmt, params=None):
            calls.append(str(stmt))

        def rollback(self):
            calls.append("ROLLBACK")

        def commit(self):
            calls.append("COMMIT")

        def close(self):
            calls.append("CLOSE")

    def boom(*_a, **_kw):
        raise RuntimeError("relation does not exist")

    monkeypatch.setattr(am, "migrate_artifacts", boom)
    with pytest.raises(RuntimeError):
        am.run_migration(session_factory=_Session, storage=object())
    unlock = next(i for i, c in enumerate(calls) if "pg_advisory_unlock" in c)
    assert calls.index("ROLLBACK") < unlock
    assert calls[-1] == "CLOSE"
