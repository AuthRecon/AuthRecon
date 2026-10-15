"""Live-view helper: display/port allocation, process setup, teardown and the
run.vnc_port lifecycle that gates the portal's VNC proxy."""
from __future__ import annotations

import os
import subprocess
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import vnc_session as vs


# --- allocation -------------------------------------------------------------


def test_ports_follow_display_number():
    assert vs.ports_for_display(100) == (5901, 6081)
    assert vs.ports_for_display(199) == (6000, 6180)


def _never(_):
    return False


def test_allocation_is_deterministic_and_in_range():
    a = vs.allocate_display("run-a", is_display_in_use=_never, is_port_in_use=_never)
    b = vs.allocate_display("run-a", is_display_in_use=_never, is_port_in_use=_never)
    assert a == b
    assert vs.DISPLAY_MIN <= a.display_num <= vs.DISPLAY_MAX
    assert (a.vnc_port, a.novnc_port) == vs.ports_for_display(a.display_num)
    assert a.display == f":{a.display_num}"


def test_allocation_skips_busy_display_and_busy_ports():
    first = vs.allocate_display("run-b", is_display_in_use=_never, is_port_in_use=_never)
    busy_display = first.display_num

    second = vs.allocate_display(
        "run-b", is_display_in_use=lambda n: n == busy_display, is_port_in_use=_never
    )
    assert second.display_num != busy_display

    busy_port = vs.ports_for_display(busy_display)[1]
    third = vs.allocate_display(
        "run-b", is_display_in_use=_never, is_port_in_use=lambda p: p == busy_port
    )
    assert third.display_num != busy_display


def test_allocation_honours_exclude():
    first = vs.allocate_display("run-c", is_display_in_use=_never, is_port_in_use=_never)
    nxt = vs.allocate_display(
        "run-c", exclude=(first.display_num,), is_display_in_use=_never, is_port_in_use=_never
    )
    assert nxt.display_num != first.display_num


def test_allocation_fails_when_everything_is_busy():
    with pytest.raises(vs.VncSessionError):
        vs.allocate_display("run-d", is_display_in_use=lambda n: True, is_port_in_use=_never)


# --- process setup / teardown -------------------------------------------------


class FakeProc:
    def __init__(self, cmd, *, exits_immediately=False, hangs_on_terminate=False):
        self.cmd = cmd
        self.returncode = 1 if exits_immediately else None
        self.terminated = False
        self.killed = False
        self._hangs = hangs_on_terminate

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        if not self._hangs:
            self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.cmd, timeout)
        return self.returncode


class FakeSystem:
    """Records spawned commands; Xvfb on ``bad_displays`` exits at once."""

    def __init__(self, *, bad_displays=(), ready=True, hang=()):
        self.procs: list[FakeProc] = []
        self.bad_displays = set(bad_displays)
        self.ready = ready
        self.hang = set(hang)

    def popen(self, cmd, **_):
        exits = cmd[0] == "Xvfb" and int(cmd[1][1:]) in self.bad_displays
        proc = FakeProc(cmd, exits_immediately=exits, hangs_on_terminate=cmd[0] in self.hang)
        self.procs.append(proc)
        return proc

    def run_cmd(self, cmd, **_):
        return SimpleNamespace(returncode=0)

    def session(self, run_id="run-x", allocate=None):
        return vs.VncSession(
            run_id,
            popen=self.popen,
            run_cmd=self.run_cmd,
            sleep=lambda _s: None,
            wait_for_port=lambda _p: self.ready,
            allocate=allocate
            or (lambda rid, exclude=(): vs.allocate_display(
                rid, exclude=exclude, is_display_in_use=_never, is_port_in_use=_never
            )),
        )

    def by_name(self, name):
        return [p for p in self.procs if p.cmd[0] == name]


def test_start_launches_localhost_only_vnc_and_websockify():
    system = FakeSystem()
    session = system.session()
    alloc = session.start()

    assert [p.cmd[0] for p in system.procs] == ["Xvfb", "x11vnc", "websockify"]
    xvfb, x11vnc, ws = system.procs
    assert xvfb.cmd[1] == alloc.display and "-nolisten" in xvfb.cmd
    # -nopw is only acceptable because x11vnc is bound to localhost.
    assert "-nopw" in x11vnc.cmd and "-localhost" in x11vnc.cmd
    assert x11vnc.cmd[x11vnc.cmd.index("-rfbport") + 1] == str(alloc.vnc_port)
    assert ws.cmd[-2:] == [str(alloc.novnc_port), f"127.0.0.1:{alloc.vnc_port}"]
    assert session.display == alloc.display and session.novnc_port == alloc.novnc_port


def test_stop_terminates_everything_newest_first_and_is_idempotent():
    system = FakeSystem()
    session = system.session()
    session.start()
    session.stop()
    assert all(p.terminated for p in system.procs)
    session.stop()  # second call is a no-op
    with pytest.raises(vs.VncSessionError):
        _ = session.display


def test_stop_kills_a_process_that_ignores_terminate():
    system = FakeSystem(hang={"websockify"})
    session = system.session()
    session.start()
    session.stop()
    ws = system.by_name("websockify")[0]
    assert ws.terminated and ws.killed


def test_websockify_never_ready_tears_down_and_raises():
    system = FakeSystem(ready=False)
    session = system.session()
    with pytest.raises(vs.VncSessionError):
        session.start()
    assert len(system.procs) == 3
    assert all(p.terminated or p.returncode is not None for p in system.procs)
    assert session.allocation is None


def test_taken_display_falls_through_to_another():
    first = vs.allocate_display("run-y", is_display_in_use=_never, is_port_in_use=_never)
    system = FakeSystem(bad_displays={first.display_num})
    session = system.session("run-y")
    alloc = session.start()
    assert alloc.display_num != first.display_num
    assert len(system.by_name("Xvfb")) == 2


def test_display_env_sets_and_restores(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":0")
    with vs.display_env(":123"):
        assert os.environ["DISPLAY"] == ":123"
    assert os.environ["DISPLAY"] == ":0"

    monkeypatch.delenv("DISPLAY")
    with vs.display_env(":124"):
        assert os.environ["DISPLAY"] == ":124"
    assert "DISPLAY" not in os.environ


# --- run.vnc_port lifecycle ---------------------------------------------------


class FakeRunModel:
    pass


class FakeDB:
    def __init__(self, run):
        self.run = run
        self.commits = 0
        self.rollbacks = 0

    def get(self, _model, run_id):
        return self.run if run_id == self.run.id else None

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def _run():
    return SimpleNamespace(id="run-z", vnc_port=None, submitted_by_profile_id="p1")


def test_live_view_publishes_port_and_clears_it_after_run(monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    run = _run()
    db = FakeDB(run)
    system = FakeSystem()
    with vs.live_view(db, run.id, session_factory=lambda rid: system.session(rid), run_model=FakeRunModel) as session:
        assert run.vnc_port == session.novnc_port
        assert os.environ["DISPLAY"] == session.allocation.display
    assert run.vnc_port is None
    assert "DISPLAY" not in os.environ
    assert all(p.terminated for p in system.procs)


def test_live_view_clears_port_when_run_errors():
    run = _run()
    db = FakeDB(run)
    system = FakeSystem()
    with pytest.raises(RuntimeError):
        with vs.live_view(db, run.id, session_factory=lambda rid: system.session(rid), run_model=FakeRunModel):
            assert run.vnc_port is not None
            raise RuntimeError("automation blew up")
    assert run.vnc_port is None
    assert all(p.terminated for p in system.procs)


def test_live_view_start_failure_publishes_nothing():
    run = _run()
    db = FakeDB(run)
    system = FakeSystem(ready=False)
    with pytest.raises(vs.VncSessionError):
        with vs.live_view(db, run.id, session_factory=lambda rid: system.session(rid), run_model=FakeRunModel):
            pytest.fail("body must not run")
    assert run.vnc_port is None


def test_internal_vnc_lookup_404s_once_the_run_finishes(monkeypatch):
    from app.api import vnc_portal

    secret = os.environ["PORTAL_API_SECRET"]
    run = _run()
    db = FakeDB(run)
    request = SimpleNamespace(
        headers={"X-Portal-Secret": secret, "X-Portal-User-Id": "1", "X-Portal-Is-Admin": "true"}
    )
    system = FakeSystem()
    with vs.live_view(db, run.id, session_factory=lambda rid: system.session(rid), run_model=FakeRunModel) as session:
        assert vnc_portal.get_vnc_info(run.id, request, db)["vnc_port"] == session.novnc_port

    with pytest.raises(HTTPException) as exc:
        vnc_portal.get_vnc_info(run.id, request, db)
    assert exc.value.status_code == 404
