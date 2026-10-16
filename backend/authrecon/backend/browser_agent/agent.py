"""AuthRecon browser agent: runs the browsers that visit target sites, in a
container that holds no AuthRecon secrets and cannot reach the database, Redis
or MCP (docker-compose `authrecon-browser`, BROWSER_ISOLATION=true).

The worker and the API ask it for a browser session and drive it remotely:
- engine "selenium": a chromedriver on its own port (webdriver_url);
- engine "playwright": a Playwright server on its own port (ws_endpoint).
Each session gets a scratch directory under SHARE_DIR (a volume shared with
the worker) for files the browser writes, such as Playwright HAR captures.
POST /displays starts a virtual display + VNC (the worker's VncSession) for a
run's live view; sessions started with that display render on it.

Requests need X-Browser-Token == BROWSER_AGENT_TOKEN (no token: refuse to start).
A browser exploit here finds no keys, credentials (beyond the one login being
typed) or database access. Deliberately not part of the `app` package, which
needs the master secrets to import.
"""
from __future__ import annotations

import hmac
import importlib.util
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

TOKEN = os.environ.get("BROWSER_AGENT_TOKEN", "")
HOST = os.environ.get("BROWSER_AGENT_HOST", "authrecon-browser")
SHARE_DIR = Path(os.environ.get("BROWSER_SHARE_DIR", "/tmp/browser-share"))
CHROMEDRIVER = os.environ.get("CHROMEDRIVER_PATH", "/usr/bin/chromedriver")
MAX_SESSIONS = int(os.environ.get("BROWSER_MAX_SESSIONS", "8"))
SESSION_TTL_SECONDS = int(os.environ.get("BROWSER_SESSION_TTL", "2400"))
PORT_RANGE = range(9600, 9700)

if len(TOKEN) < 32:
    raise SystemExit("Set BROWSER_AGENT_TOKEN (32+ characters) for authrecon-browser")

app = FastAPI(title="AuthRecon browser agent", docs_url=None, redoc_url=None, openapi_url=None)
_lock = threading.Lock()
_sessions: dict[str, dict] = {}
_displays: dict[str, dict] = {}


def _load_vnc_session_module():
    """The worker's VncSession (Xvfb + x11vnc + websockify), loaded as a plain
    file: importing the `app` package would need AuthRecon's secrets."""
    path = Path(__file__).resolve().parents[1] / "app" / "services" / "vnc_session.py"
    spec = importlib.util.spec_from_file_location("authrecon_vnc_session", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


_vnc = _load_vnc_session_module()


def _auth(x_browser_token: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_browser_token.encode(), TOKEN.encode()):
        raise HTTPException(status_code=401, detail="Bad browser agent token")


def _free_port() -> int:
    used = {s["port"] for s in _sessions.values()}
    for port in PORT_RANGE:
        if port in used:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("0.0.0.0", port))
            except OSError:
                continue
        return port
    raise HTTPException(status_code=503, detail="No free browser ports")


def _wait_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _kill(session: dict) -> None:
    proc = session.get("proc")
    if proc and proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass
    shutil.rmtree(session.get("dir", ""), ignore_errors=True)


def _reaper() -> None:
    while True:
        time.sleep(30)
        now = time.time()
        with _lock:
            expired = [sid for sid, s in _sessions.items()
                       if now - s["started"] > SESSION_TTL_SECONDS or (s["proc"].poll() is not None)]
            for sid in expired:
                _kill(_sessions.pop(sid))
            stale = [did for did, d in _displays.items() if now - d["started"] > SESSION_TTL_SECONDS]
            for did in stale:
                _displays.pop(did)["session"].stop()


threading.Thread(target=_reaper, daemon=True).start()


class SessionIn(BaseModel):
    engine: str  # "selenium" | "playwright"
    display: str | None = None  # ":N" of a display from POST /displays (headful); None = headless


class DisplayIn(BaseModel):
    run_id: str


@app.post("/displays", dependencies=[Depends(_auth)])
def start_display(payload: DisplayIn) -> dict:
    """A virtual display with VNC for a run's live view / manual recording.
    websockify listens on the browser network; the portal's authenticated
    proxy is the only client."""
    with _lock:
        if len(_displays) >= MAX_SESSIONS:
            raise HTTPException(status_code=503, detail="Too many live views")
    session = _vnc.VncSession(payload.run_id)
    try:
        session.start()
    except Exception as exc:
        session.stop()
        raise HTTPException(status_code=503, detail=f"Live view did not start: {exc}") from None
    display_id = secrets.token_hex(8)
    with _lock:
        _displays[display_id] = {"session": session, "started": time.time()}
    return {"display_id": display_id, "display": session.display, "novnc_port": session.novnc_port}


@app.delete("/displays/{display_id}", dependencies=[Depends(_auth)])
def stop_display(display_id: str) -> dict:
    with _lock:
        entry = _displays.pop(display_id, None)
    if entry:
        entry["session"].stop()
    return {"stopped": bool(entry)}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "sessions": len(_sessions)}


@app.post("/sessions", dependencies=[Depends(_auth)])
def start_session(payload: SessionIn) -> dict:
    if payload.engine not in ("selenium", "playwright"):
        raise HTTPException(status_code=400, detail="engine must be selenium or playwright")
    with _lock:
        if len(_sessions) >= MAX_SESSIONS:
            raise HTTPException(status_code=503, detail="Too many browser sessions")
        session_id = secrets.token_hex(8)
        port = _free_port()
        workdir = SHARE_DIR / session_id
        workdir.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "HOME": str(workdir)}
        env.pop("BROWSER_AGENT_TOKEN", None)  # browsers never see the agent's token
        if payload.display:
            if payload.display not in {d["session"].display for d in _displays.values()}:
                shutil.rmtree(workdir, ignore_errors=True)
                raise HTTPException(status_code=400, detail="Unknown display")
            env["DISPLAY"] = payload.display
        if payload.engine == "selenium":
            cmd = [CHROMEDRIVER, f"--port={port}", "--allowed-ips=", "--allowed-origins=*"]
        else:
            cmd = ["python", "-m", "playwright", "run-server", "--port", str(port), "--host", "0.0.0.0"]
        proc = subprocess.Popen(cmd, env=env, cwd=workdir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        session = {"proc": proc, "port": port, "dir": str(workdir), "started": time.time(), "engine": payload.engine}
        _sessions[session_id] = session
    if not _wait_port(port):
        with _lock:
            _kill(_sessions.pop(session_id, session))
        raise HTTPException(status_code=503, detail="Browser did not start")
    out = {"session_id": session_id, "share_dir": str(workdir)}
    if payload.engine == "selenium":
        out["webdriver_url"] = f"http://{HOST}:{port}"
    else:
        out["ws_endpoint"] = f"ws://{HOST}:{port}/"
    return out


@app.delete("/sessions/{session_id}", dependencies=[Depends(_auth)])
def stop_session(session_id: str) -> dict:
    with _lock:
        session = _sessions.pop(session_id, None)
    if session:
        _kill(session)
    return {"stopped": bool(session)}


if __name__ == "__main__":
    import uvicorn

    SHARE_DIR.mkdir(parents=True, exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("BROWSER_AGENT_PORT", "9500")))
