import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, List

from pydantic import AnyUrl, Field, TypeAdapter, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


# Release version; must match the repo-root VERSION file (backend/authrecon/backend/tests/test_version.py).
APP_VERSION = "0.11.0"

_ANY_URL = TypeAdapter(AnyUrl)


class Settings(BaseSettings):
    # Each field is read from the environment variable of the same name
    # (case-insensitive), except artifact_storage_dir (ARTIFACTS_DIR).
    # extra="ignore": the .env file also holds keys other code reads (as v1 did).
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore")

    app_name: str = "Auth Recon API"
    api_v1_prefix: str = "/api/v1"
    environment: str = "development"
    secret_key: str = "change-me"
    jwt_secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    credential_encryption_key: str | None = None

    # CORS: a JSON list or a comma-separated string. NoDecode stops
    # pydantic-settings from requiring JSON, so the validator below sees the raw value.
    allowed_origins: Annotated[List[str], NoDecode] = Field(
        default=["http://localhost:5173"],
        description="Comma-separated list of allowed CORS origins",
    )

    # Placeholder storage backing
    artifact_bucket: str = "authrecon-artifacts"
    artifact_storage_dir: Path = Field(Path("/app/data/artifacts"), validation_alias="ARTIFACTS_DIR")

    portal_api_secret: str = "change-me"
    # URLs stay plain strings (validated as URLs, passed on exactly as written):
    # SQLAlchemy and Redis take strings, and pydantic v2's URL type would
    # normalise them (e.g. add a trailing slash).
    portal_service_url: str = "http://portal:9000"
    portal_service_timeout: int = 5
    portal_service_id: str = "auth_recon"

    # Infrastructure
    database_url: str = "postgresql+psycopg2://authrecon:authrecon@localhost:5432/authrecon"
    redis_url: str = "redis://:authrecon@localhost:6379/0"

    @field_validator("portal_service_url", "database_url", "redis_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        _ANY_URL.validate_python(value)
        return value

    @field_validator("allowed_origins", mode="before")
    @classmethod
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

    @field_validator("secret_key", "jwt_secret_key", "portal_api_secret")
    @classmethod
    def reject_default_secrets(cls, value: str, info: ValidationInfo) -> str:
        # Fail closed: never sign/verify tokens or derive encryption keys from a
        # publicly-known default. install.sh / setup-env.sh must supply real values.
        if not value or value in {"change-me", "CHANGE_ME_GENERATE_RANDOM_KEY", "dev-portal-secret"}:
            raise ValueError(
                f"{info.field_name} must be set to a strong random value, not a known default. "
                "Run install.sh / setup-env.sh or set it in the service .env."
            )
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
