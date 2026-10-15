"""API Key model for CLI authentication.

API keys provide an alternative authentication method to JWT tokens,
designed for CLI tools, scripts, and automation workflows.

Security Features:
- Keys are hashed with bcrypt (never stored in plaintext)
- Prefix shown for identification (last 4 chars of key)
- Revocation support
- Expiration support
- Usage tracking (last_used_at)
- Audit logging ready
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, relationship

from app.db.base import Base


class APIKey(Base):
    """
    API Key for CLI/programmatic authentication.

    Each key is tied to a specific profile and can be revoked independently.
    Keys are hashed before storage (never stored in plaintext).
    """
    __tablename__ = "api_keys"

    # Primary key (not the actual API key - that's stored hashed)
    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))

    # Owner profile (foreign key)
    profile_id: Mapped[str] = Column(
        String(36),
        ForeignKey("authrecon_profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Profile that owns this API key"
    )

    # Key identification
    name: Mapped[str] = Column(
        String(150),
        nullable=False,
        comment="User-provided name for this key (e.g., 'CI/CD Pipeline', 'Dev Laptop')"
    )

    key_hash: Mapped[str] = Column(
        Text,
        nullable=False,
        unique=True,
        index=True,
        comment="bcrypt hash of the API key (never store plaintext)"
    )

    prefix: Mapped[str] = Column(
        String(20),
        nullable=False,
        comment="Display prefix for UI (e.g., 'ak_...xJ7k') - first 3 and last 4 chars"
    )

    # Lifecycle management
    is_revoked: Mapped[bool] = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        index=True,
        comment="True if key has been revoked"
    )

    revoked_at: Mapped[datetime | None] = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the key was revoked"
    )

    expires_at: Mapped[datetime | None] = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Optional expiration time for the key"
    )

    # Usage tracking
    created_at: Mapped[datetime] = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When the key was created"
    )

    last_used_at: Mapped[datetime | None] = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last successful authentication with this key"
    )

    last_mcp_used_at: Mapped[datetime | None] = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last time an MCP client connected with this key"
    )

    # Relationships
    profile = relationship("AuthReconProfile", back_populates="api_keys")

    def __repr__(self) -> str:
        return f"<APIKey(id={self.id}, name={self.name}, profile_id={self.profile_id}, revoked={self.is_revoked})>"

    def is_valid(self) -> bool:
        """Check if this API key is currently valid (not revoked, not expired)."""
        if self.is_revoked:
            return False

        if self.expires_at and self.expires_at < datetime.now(timezone.utc):
            return False

        return True
