"""Per-run virtual display + VNC for live browser viewing.

Used by manual recording and by automated runs with ``streaming_enabled``.

Topology (no host ports are published for any of this):
    Xvfb :N  ->  x11vnc (127.0.0.1:vnc_port, -localhost)  ->  websockify (novnc_port)
websockify listens on the worker's internal Docker network so the portal's
authenticated WebSocket proxy (/apps/authrecon/vnc/{run_id}, one-time ticket +
owner check) can reach it. x11vnc runs without a password, which is only
acceptable because it is bound to localhost and reachable solely through
websockify.

``run.vnc_port`` is published only once websockify accepts connections, and is
always cleared on exit so /internal/vnc/{run_id} returns 404 after the run.
"""
from __future__ import annotations

import logging
import os
import socket
import subprocess
import time
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Sequence

logger = logging.getLogger(__name__)

DISPLAY_MIN = 100
DISPLAY_MAX = 199  # inclusive: up to 100 concurrent sessions
VNC_PORT_BASE = 5900
NOVNC_PORT_BASE = 6080
NOVNC_WEB_ROOT = "/opt/novnc"
SCREEN_GEOMETRY = "1920x1080x24"


class VncSessionError(RuntimeError):
    pass


@dataclass(frozen=True)
class DisplayAllocation:
    display_num: int
    vnc_port: int
    novnc_port: int

    @property
    def display(self) -> str:
        return f":{self.display_num}"


def ports_for_display(display_num: int) -> tuple[int, int]:
    offset = display_num - (DISPLAY_MIN - 1)  # :100 -> 1
    return VNC_PORT_BASE + offset, NOVNC_PORT_BASE + offset


def display_in_use(display_num: int) -> bool:
    return os.path.exists(f"/tmp/.X{display_num}-lock") or os.path.exists(
        f"/tmp/.X11-unix/X{display_num}"
    )


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            return True
    return False


def allocate_display(
    run_id: str,
    *,
    exclude: Sequence[int] = (),
    is_display_in_use: Callable[[int], bool] = display_in_use,
    is_port_in_use: Callable[[int], bool] = port_in_use,
) -> DisplayAllocation:
    """Pick a free display (and its ports), starting from a stable per-run slot.

    The start slot comes from a deterministic hash of the run id so concurrent
    runs spread out; from there we probe linearly for a display whose lock file
    and both ports are free.
    """
    span = DISPLAY_MAX - DISPLAY_MIN + 1
    start = zlib.crc32(run_id.encode("utf-8")) % span
    for step in range(span):
        display_num = DISPLAY_MIN + (start + step) % span
        if display_num in exclude or is_display_in_use(display_num):
            continue
        vnc_port, novnc_port = ports_for_display(display_num)
        if is_port_in_use(vnc_port) or is_port_in_use(novnc_port):
            continue
        return DisplayAllocation(display_num, vnc_port, novnc_port)
    raise VncSessionError("No free virtual display available for live viewing")


def _wait_for_port(port: int, *, attempts: int, delay: float, sleep: Callable[[float], None]) -> bool:
    for _ in range(attempts):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            sleep(delay)
    return False


class VncSession:
    """Starts Xvfb + x11vnc + websockify for one run; ``stop()`` always cleans up."""

    def __init__(
        self,
        run_id: str,
        *,
        popen: Callable[..., Any] = subprocess.Popen,
        run_cmd: Callable[..., Any] = subprocess.run,
        sleep: Callable[[float], None] = time.sleep,
        wait_for_port: Callable[[int], bool] | None = None,
        allocate: Callable[..., DisplayAllocation] = allocate_display,
        max_display_attempts: int = 3,
    ) -> None:
        self.run_id = run_id
        self._popen = popen
        self._run_cmd = run_cmd
        self._sleep = sleep
        self._wait_for_port = wait_for_port or (
            lambda port: _wait_for_port(port, attempts=30, delay=0.5, sleep=sleep)
        )
        self._allocate = allocate
        self._max_display_attempts = max_display_attempts
        self.allocation: DisplayAllocation | None = None
        self._procs: list[Any] = []

    @property
    def display(self) -> str:
        if not self.allocation:
            raise VncSessionError("VNC session not started")
        return self.allocation.display

    @property
    def novnc_port(self) -> int:
        if not self.allocation:
            raise VncSessionError("VNC session not started")
        return self.allocation.novnc_port

    def _spawn(self, cmd: list[str]) -> Any:
        proc = self._popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._procs.append(proc)
        return proc

    def _start_xvfb(self, allocation: DisplayAllocation) -> bool:
        proc = self._spawn(
            # -nolisten tcp: the display is only reachable via the container-local socket.
            ["Xvfb", allocation.display, "-screen", "0", SCREEN_GEOMETRY, "-ac", "-nolisten", "tcp"]
        )
        for _ in range(20):
            if proc.poll() is not None:
                return False  # exited: display taken by someone else
            result = self._run_cmd(
                ["xdpyinfo", "-display", allocation.display],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                return True
            self._sleep(0.5)
        return False

    def start(self) -> DisplayAllocation:
        tried: list[int] = []
        for _ in range(self._max_display_attempts):
            allocation = self._allocate(self.run_id, exclude=tuple(tried))
            tried.append(allocation.display_num)
            if self._start_xvfb(allocation):
                self.allocation = allocation
                break
            self.stop()
        else:
            raise VncSessionError("Could not start a virtual display")

        allocation = self.allocation
        # -localhost: never reachable off-box; only websockify connects to it.
        self._spawn(
            [
                "x11vnc", "-display", allocation.display, "-localhost",
                "-rfbport", str(allocation.vnc_port),
                "-forever", "-shared", "-nopw", "-quiet",
            ]
        )
        self._spawn(
            [
                "websockify", f"--web={NOVNC_WEB_ROOT}",
                str(allocation.novnc_port), f"127.0.0.1:{allocation.vnc_port}",
            ]
        )
        if not self._wait_for_port(allocation.novnc_port):
            self.stop()
            raise VncSessionError("Live view did not become ready in time")
        logger.info("[VNC %s] live view ready on display %s", self.run_id, allocation.display)
        return allocation

    def stop(self) -> None:
        """Terminate every process started so far (newest first). Idempotent."""
        while self._procs:
            proc = self._procs.pop()
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
            except Exception:  # pragma: no cover - best effort teardown
                logger.warning("[VNC %s] failed to stop a VNC process", self.run_id, exc_info=True)
        self.allocation = None


@contextmanager
def display_env(display: str) -> Iterator[None]:
    """Point DISPLAY at ``display`` so Selenium/Playwright render there; restore after."""
    original = os.environ.get("DISPLAY")
    os.environ["DISPLAY"] = display
    try:
        yield
    finally:
        if original is None:
            os.environ.pop("DISPLAY", None)
        else:
            os.environ["DISPLAY"] = original


def _set_vnc_port(db: Any, run_model: Any, run_id: str, port: int | None) -> None:
    run = db.get(run_model, run_id)
    if run is None:
        return
    run.vnc_port = port
    db.commit()


@contextmanager
def live_view(
    db: Any,
    run_id: str,
    *,
    session_factory: Callable[[str], VncSession] = VncSession,
    run_model: Any = None,
) -> Iterator[VncSession]:
    """Start a VNC session, publish ``run.vnc_port``, and always clear/tear down.

    On exit (normal or error) ``run.vnc_port`` is reset to ``None`` first, so the
    portal stops handing out tickets, then the processes are stopped.
    Raises ``VncSessionError`` if the session cannot start (nothing published).
    """
    if run_model is None:
        from app.models import Run as run_model  # noqa: N813

    # Browser isolation: the display lives in the browser container and the
    # run's browsers are started there (automation/remote_browser.py).
    from app.services.automation import remote_browser

    isolated = remote_browser.isolation_enabled() and session_factory is VncSession
    if isolated:
        session_factory = remote_browser.RemoteVncSession
    session = session_factory(run_id)
    try:
        session.start()
        with (remote_browser.use_display(session.display) if isolated else display_env(session.display)):
            _set_vnc_port(db, run_model, run_id, session.novnc_port)
            yield session
    finally:
        try:
            _set_vnc_port(db, run_model, run_id, None)
        except Exception:
            logger.warning("[VNC %s] could not clear vnc_port", run_id, exc_info=True)
            try:
                db.rollback()
                _set_vnc_port(db, run_model, run_id, None)
            except Exception:
                logger.error("[VNC %s] vnc_port left set after retry", run_id, exc_info=True)
        session.stop()
