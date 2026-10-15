"""Portal asset catalog model."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class PortalAsset(Base):
    """Represents a host/application/resource tracked by the portal."""

    __tablename__ = "portal_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    owner_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    sharing_scope: Mapped[str] = mapped_column(String(32), default="global", nullable=False)
    canonical_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    primary_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    alt_identifiers: Mapped[dict] = mapped_column(JSON, default=dict)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
