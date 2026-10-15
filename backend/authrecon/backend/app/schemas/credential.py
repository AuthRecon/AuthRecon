from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CredentialBase(BaseModel):
    name: str = Field(..., max_length=150)
    description: str | None = None
    auth_type: str = "generic"
    username: str
    additional_fields: dict[str, Any] = Field(default_factory=dict)


class CredentialCreate(CredentialBase):
    secret: str = Field(..., min_length=1)


class CredentialUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    auth_type: str | None = None
    username: str | None = None
    secret: str | None = Field(default=None, min_length=1)
    additional_fields: dict[str, Any] | None = None
    is_archived: bool | None = None


class CredentialRead(CredentialBase):
    id: str
    owner_user_id: str | None
    is_archived: bool
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None

    class Config:
        orm_mode = True
