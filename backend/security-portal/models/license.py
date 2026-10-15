"""Portal license management models."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class ClientLicense(Base):
    """Licenses issued by Portal admin to clients."""

    __tablename__ = "client_licenses"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    license_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    license_type: Mapped[str] = mapped_column(String(32), nullable=False)  # 'trial', 'professional', 'enterprise', 'perpetual'

    # Optional link to credential (for client tracking)
    credential_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("portal_assets.id"), nullable=True)

    # Who issued this license
    issued_by: Mapped[str] = mapped_column(String(36), ForeignKey("portal_users.id"), nullable=False)

    # Expiration (NULL = perpetual)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Management
    max_installations: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Notes
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    activations = relationship("LicenseActivation", back_populates="license", cascade="all, delete-orphan")


class LicenseActivation(Base):
    """Track installations using Portal-issued licenses."""

    __tablename__ = "license_activations"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    license_id: Mapped[str] = mapped_column(String(36), ForeignKey("client_licenses.id"), nullable=False)
    installation_id: Mapped[str] = mapped_column(String(64), nullable=False)  # From AuthRecon client
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_checked: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationship
    license = relationship("ClientLicense", back_populates="activations")
