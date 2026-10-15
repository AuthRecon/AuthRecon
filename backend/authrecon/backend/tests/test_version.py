"""Every component reports the release version in the repo-root VERSION file.
Bump VERSION and these together; this test catches the ones you missed."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
VERSION_FILE = REPO / "VERSION"

pytestmark = pytest.mark.skipif(not VERSION_FILE.exists(), reason="needs the full repo checkout")


def _expected() -> str:
    return VERSION_FILE.read_text().strip()


def _constant(path: str, name: str) -> str:
    match = re.search(rf'^{name}\s*=\s*"([^"]+)"', (REPO / path).read_text(), re.M)
    assert match, f"{name} not found in {path}"
    return match.group(1)


def test_api_version():
    from app.core.config import APP_VERSION

    assert APP_VERSION == _expected()


@pytest.mark.parametrize("path,name", [
    ("backend/security-portal/config.py", "APP_VERSION"),
    ("backend/authrecon/cli/authrecon/__init__.py", "__version__"),
])
def test_python_constants(path, name):
    assert _constant(path, name) == _expected()


def test_cli_setup_version():
    assert re.search(r'version="([^"]+)"', (REPO / "backend/authrecon/cli/setup.py").read_text()).group(1) == _expected()


def test_frontend_package_version():
    assert json.loads((REPO / "package.json").read_text())["version"] == _expected()
    lock = json.loads((REPO / "package-lock.json").read_text())
    assert lock["version"] == lock["packages"][""]["version"] == _expected()
