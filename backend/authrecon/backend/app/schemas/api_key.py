"""API Key schemas for request/response validation."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class APIKeyCreate(BaseModel):
    """Request schema for creating a new API key."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=150,
        description="User-friendly name for the API key (e.g., 'CI/CD Pipeline', 'Dev Laptop')"
    )
    expires_days: int | None = Field(
        default=None,
        ge=1,
        le=365,
        description="Optional: Number of days until expiration (1-365). Null = never expires"
    )


class APIKeyCreated(BaseModel):
    """Response schema for successful API key creation.

    IMPORTANT: The plaintext key is ONLY shown once at creation time.
    Store it securely - it cannot be retrieved again.
    """

    id: str
    name: str
    key: str = Field(
        ...,
        description="Plaintext API key - SAVE THIS! It will never be shown again."
    )
    prefix: str = Field(
        ...,
        description="Display prefix for identification (e.g., 'ak_...xJ7k')"
    )
    created_at: datetime
    expires_at: datetime | None = None


class APIKeyRead(BaseModel):
    """Response schema for listing API keys (without plaintext key)."""

    id: str
    name: str
    prefix: str = Field(
        ...,
        description="Display prefix for identification (e.g., 'ak_...xJ7k')"
    )
    is_revoked: bool
    revoked_at: datetime | None = None
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class APIKeyRevoke(BaseModel):
    """Response schema for revoking an API key."""

    id: str
    name: str
    is_revoked: bool
    revoked_at: datetime

    model_config = ConfigDict(from_attributes=True)
