import json
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import AnyUrl, BaseSettings, Field, validator


# Release version; must match the repo-root VERSION file (backend/authrecon/backend/tests/test_version.py).
APP_VERSION = "0.9.0"


class Settings(BaseSettings):
    app_name: str = "Auth Recon API"
    api_v1_prefix: str = "/api/v1"
    environment: str = "development"
    secret_key: str = Field("change-me", env="SECRET_KEY")
    jwt_secret_key: str = Field("change-me", env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field("HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(60, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    credential_encryption_key: str | None = Field(None, env="CREDENTIAL_ENCRYPTION_KEY")

    # CORS / security knobs (configured via ALLOWED_ORIGINS environment variable)
    allowed_origins: List[str] = Field(
        default=["http://localhost:5173"],
        env="ALLOWED_ORIGINS",
        description="Comma-separated list of allowed CORS origins"
    )

    # Placeholder storage backing
    artifact_bucket: str = "authrecon-artifacts"
    artifact_storage_dir: Path = Field(Path("/app/data/artifacts"), env="ARTIFACTS_DIR")

    portal_api_secret: str = Field("change-me", env="PORTAL_API_SECRET")
    portal_service_url: AnyUrl = Field("http://portal:9000", env="PORTAL_SERVICE_URL")
    portal_service_timeout: int = Field(5, env="PORTAL_SERVICE_TIMEOUT")
    portal_service_id: str = Field("auth_recon", env="PORTAL_SERVICE_ID")

    # Infrastructure
    database_url: AnyUrl = Field(
        "postgresql+psycopg2://authrecon:authrecon@localhost:5432/authrecon",
        env="DATABASE_URL",
    )
    redis_url: AnyUrl = Field(
        "redis://:authrecon@localhost:6379/0",
        env="REDIS_URL",
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @validator("allowed_origins", pre=True)
    def parse_allowed_origins(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, list):
                        return [str(origin).strip() for origin in parsed if str(origin).strip()]
                except json.JSONDecodeError:
                    pass
            return [origin.strip() for origin in stripped.split(",") if origin.strip()]
        return value

    @validator("secret_key", "jwt_secret_key", "portal_api_secret")
    def reject_default_secrets(cls, value: str, field) -> str:
        # Fail closed: never sign/verify tokens or derive encryption keys from a
        # publicly-known default. install.sh / setup-env.sh must supply real values.
        if not value or value in {"change-me", "CHANGE_ME_GENERATE_RANDOM_KEY", "dev-portal-secret"}:
            raise ValueError(
                f"{field.name} must be set to a strong random value, not a known default. "
                "Run install.sh / setup-env.sh or set it in the service .env."
            )
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
