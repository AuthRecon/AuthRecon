"""Database models for the forthcoming web scanner module."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from sqlalchemy import Column, DateTime, Enum as SAEnum, ForeignKey, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship

from app.db.base import Base


def _enum_values(enum_cls: type[Enum]) -> list[str]:
    """Force SQLAlchemy to persist Enum values (lowercase) instead of Enum names (uppercase)."""
    return [member.value for member in enum_cls]


class ScannerStatus(str, Enum):
    """Possible states for a scanner run."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class Asset(Base):
    """Normalized asset table shared across AuthRecon and the scanner."""

    __tablename__ = "assets"

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    hostname: Mapped[str] = Column(String(255), nullable=False)
    ip_address: Mapped[str | None] = Column(String(64))
    url: Mapped[str | None] = Column(Text)
    labels: Mapped[list[str]] = Column(JSONB, default=list)
    extra_metadata: Mapped[dict] = Column(JSONB, default=dict)
    created_at: Mapped[datetime] = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    scanner_runs = relationship("ScannerRun", back_populates="asset")
    findings = relationship("ScannerFinding", back_populates="asset")


class ScannerRun(Base):
    """Represents a single execution of the WAS module."""

    __tablename__ = "scanner_runs"

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_url: Mapped[str] = Column(Text, nullable=False)
    engine: Mapped[str] = Column(String(50), nullable=False, default="nuclei")
    template_set: Mapped[str | None] = Column(Text)
    status: Mapped[ScannerStatus] = Column(
        SAEnum(
            ScannerStatus,
            name="scanner_status",
            values_callable=_enum_values,
            create_type=False,
            validate_strings=True,
        ),
        nullable=False,
        default=ScannerStatus.QUEUED,
    )
    asset_id: Mapped[str | None] = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"))
    auth_run_id: Mapped[str | None] = Column(String(36), ForeignKey("runs.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    started_at: Mapped[datetime | None] = Column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = Column(DateTime(timezone=True))
    notes: Mapped[str | None] = Column(Text)
    extra_metadata: Mapped[dict] = Column(JSONB, default=dict)

    asset = relationship("Asset", back_populates="scanner_runs")
    findings = relationship(
        "ScannerFinding",
        back_populates="scanner_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    auth_run = relationship("Run")


class ScannerFinding(Base):
    """Individual finding produced by a scanner run."""

    __tablename__ = "scanner_findings"

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scanner_run_id: Mapped[str] = Column(
        String(36),
        ForeignKey("scanner_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[str | None] = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"))
    severity: Mapped[str] = Column(String(20), nullable=False)
    title: Mapped[str] = Column(String(255), nullable=False)
    description: Mapped[str | None] = Column(Text)
    evidence: Mapped[str | None] = Column(Text)
    recommendation: Mapped[str | None] = Column(Text)
    cwe: Mapped[str | None] = Column(String(50))
    cve: Mapped[str | None] = Column(String(50))
    cvss: Mapped[float | None] = Column(Numeric(4, 2))
    references: Mapped[list[str]] = Column(JSONB, default=list)
    detected_at: Mapped[datetime] = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    scanner_run = relationship("ScannerRun", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
