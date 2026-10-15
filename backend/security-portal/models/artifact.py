"""Encrypted artifact storage for module outputs."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, JSON, LargeBinary, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class PortalArtifact(Base):
    """Stores module outputs linked to portal assets."""

    __tablename__ = "portal_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("portal_assets.id", ondelete="SET NULL"))
    owner_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    sharing_scope: Mapped[str] = mapped_column(String(32), default="global", nullable=False)
    module: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    encrypted_blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
