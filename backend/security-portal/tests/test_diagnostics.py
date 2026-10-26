"""Network Tools (ping/traceroute/nslookup): targets can't smuggle in flags or
odd text, and a timed-out run still returns its partial output."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import diagnostics  # noqa: E402
from diagnostics import DiagnosticsManager, _validate_target  # noqa: E402


@pytest.mark.parametrize("target", ["example.com", "sub.example-host.org", "10.0.0.1", "::1", "localhost"])
def test_valid_targets_pass(target):
    _validate_target(target)


@pytest.mark.parametrize("target", [
    "-f",                    # would become a ping flag
    "example.com\n",         # '$' alone would let a trailing newline through
    "fe80::1%-f",            # IPv6 zone ids take arbitrary text
    "example.com; id",
    "a b",
    "$(id)",
    "exa_mple.com",
])
def test_bad_targets_rejected(target):
    with pytest.raises(ValueError):
        _validate_target(target)


class _FakeStore:
    def __init__(self):
        self.created = []

    def resolve(self, **kwargs):
        return SimpleNamespace(id="asset-1")

    def create(self, **kwargs):
        self.created.append(kwargs)
        return SimpleNamespace(id="artifact-1")


def test_timeout_keeps_partial_output(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b" 1  10.0.0.1  0.5 ms\n")

    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)
    store = _FakeStore()
    manager = DiagnosticsManager(store, store)
    user = SimpleNamespace(user_id="u1", username="u1")

    result = manager.run_tool(tool="traceroute", target="10.0.0.1", private=True, user=user)

    assert result.exit_code == -1
    blob = store.created[0]["blob"]
    assert "10.0.0.1  0.5 ms" in blob
    assert "timed out" in blob
