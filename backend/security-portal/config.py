"""Portal configuration loader."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

from dotenv import load_dotenv

# Release version; must match the repo-root VERSION file (backend/authrecon/backend/tests/test_version.py).
APP_VERSION = "0.9.0"



@dataclass(frozen=True)
class PortalConfig:
    """Configuration values for the portal."""

    portal_name: str
    secret_key: str
    allowed_users: List[str]
    admin_users: List[str]
    tools_config_path: Path
    log_path: Path
    authrecon_api_base_url: str
    mcp_base_url: str
    portal_api_secret: str
    env_label: str
    portal_version: str
    user_store_path: Path
    encryption_key_path: Path
    database_url: str
    license_server_url: str
    license_cache_path: Path
    license_check_interval_days: int
    license_offline_grace_days: int
    redis_url: str


def load_config(env_path: Path | None = None) -> PortalConfig:
    """Load configuration from .env + environment."""
    env_path = env_path or Path(".env")
    if env_path.exists():
        load_dotenv(env_path)

    portal_name = os.getenv("PORTAL_NAME", "Security Tools Portal")
    # Signing secret for portal session cookies and user JWTs. Accept either name
    # (installers historically wrote JWT_SECRET_KEY) and fail closed on the known
    # default so a misconfigured deploy can never silently sign tokens with a
    # publicly-known constant.
    secret_key = os.getenv("PORTAL_SECRET_KEY") or os.getenv("JWT_SECRET_KEY") or ""
    if not secret_key or secret_key in {"change-me", "CHANGE_ME_GENERATE_RANDOM_KEY"}:
        raise RuntimeError(
            "Portal signing secret is unset or using a known default. "
            "Set PORTAL_SECRET_KEY (or JWT_SECRET_KEY) to a strong random value."
        )
    allowed_users = [u.strip().lower() for u in os.getenv("PORTAL_ALLOWED_USERS", "*").split(",")]
    tools_config_path = Path(os.getenv("TOOLS_CONFIG_PATH", "tools.yaml"))
    log_path = Path(os.getenv("PORTAL_LOG_PATH", "logs/portal.log"))
    admin_users = [user.strip().lower() for user in os.getenv("PORTAL_ADMIN_USERS", "").split(",") if user.strip()]
    authrecon_api_base_url = os.getenv("AUTHRECON_API_BASE_URL", "http://authrecon-api:8000/api/v1").rstrip("/")
    mcp_base_url = os.getenv("MCP_BASE_URL", "http://authrecon-mcp:8765").rstrip("/")
    # Shared signing secret for service-to-service JWTs (authrecon-api
    # verifies against this). Fail closed on the known default for
    # the same reason as the portal signing secret above — a misconfigured deploy
    # must never silently accept tokens signed with a publicly-known constant.
    portal_api_secret = os.getenv("PORTAL_API_SECRET", "")
    if not portal_api_secret or portal_api_secret in {"change-me", "dev-portal-secret"}:
        raise RuntimeError(
            "PORTAL_API_SECRET is unset or using a known default. "
            "Set PORTAL_API_SECRET to a strong random value shared by all services."
        )
    env_label = os.getenv("PORTAL_ENV_LABEL", "Development Use Only")
    portal_version = os.getenv("PORTAL_VERSION", "0.1.0-dev")
    user_store_path = Path(os.getenv("PORTAL_USER_STORE", "data/portal_users.json"))
    if not user_store_path.is_absolute():
        user_store_path = (Path.cwd() / user_store_path).resolve()
    user_store_path.parent.mkdir(parents=True, exist_ok=True)

    encryption_key_path = Path(os.getenv("PORTAL_ENCRYPTION_KEY_PATH", "data/portal.key"))
    if not encryption_key_path.is_absolute():
        encryption_key_path = (Path.cwd() / encryption_key_path).resolve()
    encryption_key_path.parent.mkdir(parents=True, exist_ok=True)

    database_url = os.getenv("PORTAL_DATABASE_URL", "sqlite:///data/portal.db")

    license_server_url = os.getenv("PORTAL_LICENSE_SERVER", "")
    license_cache_path = Path(os.getenv("PORTAL_LICENSE_CACHE", "data/license_status.json"))
    if not license_cache_path.is_absolute():
        license_cache_path = (Path.cwd() / license_cache_path).resolve()
    license_cache_path.parent.mkdir(parents=True, exist_ok=True)
    license_check_interval_days = int(os.getenv("PORTAL_LICENSE_CHECK_INTERVAL_DAYS", "14"))
    license_offline_grace_days = int(os.getenv("PORTAL_LICENSE_OFFLINE_GRACE_DAYS", "30"))
    redis_url = os.getenv("REDIS_URL", "redis://:authrecon@authrecon-redis:6379/1")

    if database_url.startswith("sqlite:///"):
        raw_path = database_url.replace("sqlite:///", "", 1)
        db_path = Path(raw_path)
        if not db_path.is_absolute():
            db_path = (Path.cwd() / db_path).resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        database_url = f"sqlite:///{db_path}"

    from auth import configure_serializer

    configure_serializer(secret_key)

    log_path.parent.mkdir(parents=True, exist_ok=True)

    return PortalConfig(
        portal_name=portal_name,
        secret_key=secret_key,
        allowed_users=allowed_users,
        admin_users=admin_users,
        tools_config_path=tools_config_path,
        log_path=log_path,
        authrecon_api_base_url=authrecon_api_base_url,
        mcp_base_url=mcp_base_url,
        portal_api_secret=portal_api_secret,
        env_label=env_label,
        portal_version=portal_version,
        user_store_path=user_store_path,
        encryption_key_path=encryption_key_path,
        database_url=database_url,
        license_server_url=license_server_url,
        license_cache_path=license_cache_path,
        license_check_interval_days=license_check_interval_days,
        license_offline_grace_days=license_offline_grace_days,
        redis_url=redis_url,
    )
