"""AuthRecon user profile model.

This model stores ONLY AuthRecon-specific per-user data.
User identity (username, password, is_admin, is_active) lives in Portal database.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, String, Text
from sqlalchemy.orm import Mapped, relationship

from app.db.base import Base


class AuthReconProfile(Base):
    """
    Per-user profile for AuthRecon service.

    This is NOT a user identity model. It only stores AuthRecon-specific settings
    for Portal users. Identity fields (username, password, is_admin) remain in Portal.
    """
    __tablename__ = "authrecon_profiles"

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))

    # ONLY identity reference - points to Portal.PortalUser.id
    portal_user_id: Mapped[str] = Column(
        String(36),
        nullable=False,
        unique=True,
        index=True,
        comment="Foreign key to Portal database PortalUser.id"
    )

    # AuthRecon-specific profile data
    artifact_key_encrypted: Mapped[str | None] = Column(
        Text,
        nullable=True,
        comment="Encrypted per-user key for credential artifacts"
    )
    llm_enabled: Mapped[bool] = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="Enable LLM features for this user"
    )

    # Profile timestamps
    created_at: Mapped[datetime] = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    display_name: Mapped[str | None] = Column(
        String(150),
        nullable=True,
        comment="Portal username, refreshed at each login; used to attribute API-key/MCP actions"
    )
    last_login_at: Mapped[datetime | None] = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last login timestamp for this profile"
    )

    # API access control
    api_access_enabled: Mapped[bool] = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="Admin-controlled flag: allow this user to generate API keys"
    )

    # Relationships to AuthRecon-specific data
    credentials = relationship(
        "StoredCredential",
        back_populates="owner",
        cascade="all, delete-orphan",
    )

    api_keys = relationship(
        "APIKey",
        back_populates="profile",
        cascade="all, delete-orphan",
    )

    audit_events = relationship(
        "AuditLog",
        back_populates="actor",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<AuthReconProfile(id={self.id}, portal_user_id={self.portal_user_id})>"
