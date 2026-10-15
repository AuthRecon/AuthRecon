"""Uploaded Tenable WAS scan exports for the (MCP-only) scan analyzer.

The zip itself is stored encrypted at rest (ARENC, owner's artifact key) via
ArtifactStorage; this row holds metadata and the parser's summary. Exports can
contain scan configuration including target credentials, so the raw zip is
never returned to an AI client: MCP tools only see the sanitized summary.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, relationship

from app.db.base import Base


class ScanExport(Base):
    __tablename__ = "scan_exports"

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    owner_profile_id: Mapped[str] = Column(
        String(36), ForeignKey("authrecon_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    filename: Mapped[str] = Column(String(255), nullable=False)
    size_bytes: Mapped[int] = Column(Integer, nullable=False, default=0)
    sha256: Mapped[str] = Column(String(64), nullable=False)
    storage_path: Mapped[str] = Column(Text, nullable=False)
    # uploaded -> parsed | failed. Analysis states come later with the real parser.
    status: Mapped[str] = Column(String(32), nullable=False, default="uploaded")
    summary: Mapped[dict[str, Any] | None] = Column(JSON, nullable=True)
    error: Mapped[str | None] = Column(Text, nullable=True)
    created_at: Mapped[datetime] = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True
    )
    parsed_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)

    owner = relationship("AuthReconProfile")
