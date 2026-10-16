from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services.credential_domains import normalize_domains


class CredentialBase(BaseModel):
    name: str = Field(..., max_length=150)
    description: str | None = None
    auth_type: str = "generic"
    username: str
    additional_fields: dict[str, Any] = Field(default_factory=dict)
    # Hosts it may be used on: "app.example.com" or "*.example.com". Empty = bound
    # to the first run's target host.
    allowed_domains: list[str] = Field(default_factory=list)

    @field_validator("allowed_domains", mode="before")
    @classmethod
    def _domains(cls, value):
        return normalize_domains(value or [])


class CredentialCreate(CredentialBase):
    secret: str = Field(..., min_length=1)


class CredentialUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    auth_type: str | None = None
    username: str | None = None
    secret: str | None = Field(default=None, min_length=1)
    additional_fields: dict[str, Any] | None = None
    allowed_domains: list[str] | None = None
    is_archived: bool | None = None

    @field_validator("allowed_domains", mode="before")
    @classmethod
    def _domains(cls, value):
        return None if value is None else normalize_domains(value)


class CredentialRead(CredentialBase):
    id: str
    owner_user_id: str | None = None
    is_archived: bool
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
