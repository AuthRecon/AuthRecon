from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship

from app.db.base import Base


class StoredCredential(Base):
    __tablename__ = "stored_credentials"

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = Column(String(150), nullable=False)
    description: Mapped[str | None] = Column(Text)
    auth_type: Mapped[str] = Column(String(100), nullable=False, default="generic")
    username: Mapped[str] = Column(String(255), nullable=False)
    secret_encrypted: Mapped[str] = Column(Text, nullable=False)
    additional_fields: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    is_archived: Mapped[bool] = Column(Boolean, nullable=False, default=False)

    owner_profile_id: Mapped[str] = Column(
        String(36),
        ForeignKey("authrecon_profiles.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

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
    last_used_at: Mapped[datetime | None] = Column(DateTime(timezone=True))

    owner = relationship("AuthReconProfile", back_populates="credentials")
    audit_events = relationship(
        "AuditLog",
        back_populates="credential",
        cascade="all, delete-orphan",
    )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = Column(String(40), primary_key=True, default=lambda: str(uuid4()))
    actor_profile_id: Mapped[str] = Column(
        String(36),
        ForeignKey("authrecon_profiles.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    credential_id: Mapped[str | None] = Column(
        String(36),
        ForeignKey("stored_credentials.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    entity_type: Mapped[str] = Column(String(50), nullable=False)
    entity_id: Mapped[str | None] = Column(String(50))
    action: Mapped[str] = Column(String(50), nullable=False)
    details: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    actor = relationship("AuthReconProfile", back_populates="audit_events")
    credential = relationship("StoredCredential", back_populates="audit_events")
