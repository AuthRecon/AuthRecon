"""Configuration management for AuthRecon CLI."""
import os
from pathlib import Path
from typing import Optional

import yaml


CONFIG_DIR = Path.home() / ".authrecon"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


def ensure_config_dir():
    """Create config directory if it doesn't exist (owner-only: it holds the API key)."""
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)


def load_config() -> dict:
    """Load configuration from file."""
    if not CONFIG_FILE.exists():
        return {}

    with open(CONFIG_FILE, "r") as f:
        return yaml.safe_load(f) or {}


def save_config(config: dict):
    """Save configuration to file."""
    ensure_config_dir()
    # Create with 0600 from the start so the API key is never world-readable,
    # and tighten an existing file written by an older version.
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(CONFIG_FILE, 0o600)
    with os.fdopen(fd, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def get_api_key() -> Optional[str]:
    """Get stored API key."""
    config = load_config()
    return config.get("api_key")


def get_api_url() -> str:
    """Get API URL (from config or default)."""
    config = load_config()
    return config.get("api_url", "http://localhost:8001/api/v1")


def set_api_key(api_key: str):
    """Store API key."""
    config = load_config()
    config["api_key"] = api_key
    save_config(config)


def set_api_url(api_url: str):
    """Store API URL."""
    config = load_config()
    config["api_url"] = api_url
    save_config(config)


def clear_config():
    """Clear all configuration."""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
