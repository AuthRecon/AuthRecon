from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship, Mapped

from app.db.base import Base
from app.schemas.run import RunStatus


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = Column(String(36), primary_key=True)
    target_url: Mapped[str] = Column(Text, nullable=False)
    status: Mapped[RunStatus] = Column(
        Enum(RunStatus, name="run_status", create_type=False),  # enum managed via Alembic
        nullable=False,
    )
    auth_type: Mapped[str | None] = Column(String(100))
    operator: Mapped[str | None] = Column(String(100))
    submitted_by_profile_id: Mapped[str | None] = Column(
        String(36),
        ForeignKey("authrecon_profiles.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    submitted_at: Mapped[datetime] = Column(DateTime(timezone=True), nullable=False, index=True)
    started_at: Mapped[datetime | None] = Column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = Column(DateTime(timezone=True))
    final_url: Mapped[str | None] = Column(Text)
    pattern: Mapped[str | None] = Column(Text)
    llm_pattern: Mapped[str | None] = Column(Text)
    session_cookies: Mapped[list[dict[str, Any]] | list[str]] = Column(JSONB, default=list)
    session_cookies_enc: Mapped[str | None] = Column(Text, nullable=True)  # Fernet-encrypted JSON; preferred over session_cookies
    options: Mapped[dict] = Column(JSONB, default=dict)
    tech_fingerprint: Mapped[dict | None] = Column(JSONB, default=dict)
    security_context: Mapped[dict | None] = Column(JSONB, default=None)
    error_message: Mapped[str | None] = Column(Text)
    flow_summary: Mapped[str | None] = Column(Text)  # Human-readable authentication flow narrative
    streaming_enabled: Mapped[bool] = Column(Boolean, nullable=False, default=False, server_default="false")  # VNC browser streaming
    vnc_port: Mapped[int | None] = Column(Integer, nullable=True)  # VNC port for manual recording sessions

    submitted_by = relationship("AuthReconProfile")

    artifacts: Mapped[List["Artifact"]] = relationship(
        "Artifact",
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    timeline_events: Mapped[List["TimelineEvent"]] = relationship(
        "TimelineEvent",
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="TimelineEvent.occurred_at"
    )


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = Column(String(40), primary_key=True)
    run_id: Mapped[str] = Column(
        String(36),
        ForeignKey("runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = Column(String(255), nullable=False)
    description: Mapped[str | None] = Column(Text)
    type: Mapped[str] = Column(String(50), nullable=False)
    size_bytes: Mapped[int] = Column(Integer, nullable=False, default=0)
    storage_path: Mapped[str | None] = Column(Text)
    download_url: Mapped[str | None] = Column(Text)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), nullable=False, index=True)
    is_encrypted: Mapped[bool] = Column(Boolean, nullable=False, default=False, server_default="false")
    role_slug: Mapped[str | None] = Column(String(64), index=True)
    run: Mapped["Run"] = relationship("Run", back_populates="artifacts")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = Column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = Column(
        String(36),
        ForeignKey("runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    occurred_at: Mapped[datetime] = Column(DateTime(timezone=True), nullable=False, index=True)
    message: Mapped[str] = Column(Text, nullable=False)

    run: Mapped["Run"] = relationship("Run", back_populates="timeline_events")
