"""
Tenant Playbook Model - Phase 4 Historical Learning

Stores successful authentication patterns that can be reused for deterministic
logins instead of heuristic detection.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from app.db.base import Base


class TenantPlaybook(Base):
    """
    Historical learning database for authentication patterns.

    After a successful authentication, this table stores:
    - Exact selectors (username field, password field, submit button)
    - Primary auth endpoint
    - Auth type classification
    - Confidence score based on success rate

    Next time the same domain is scanned, we use deterministic execution
    (reuse proven selectors) instead of heuristic detection (guess).
    """

    __tablename__ = "tenant_playbooks"

    # Primary key
    id: Mapped[str] = Column(String(36), primary_key=True)

    # Tenant/domain identification
    domain: Mapped[str] = Column(String(255), nullable=False, index=True)
    profile_id: Mapped[str | None] = Column(String(36), nullable=True, index=True)

    # Authentication pattern
    auth_type: Mapped[str] = Column(String(100), nullable=False)

    # Learned selectors (from successful runs)
    # Example: {
    #   "username_selector": "#user-email",
    #   "password_selector": "input[name='password']",
    #   "submit_selector": "button[type='submit']",
    #   "username_field_type": "id",
    #   "password_field_type": "css"
    # }
    selectors: Mapped[dict[str, Any]] = Column(
        JSONB,
        nullable=False,
        comment="Exact selectors for username, password, submit fields"
    )

    # Endpoints
    # Example: {
    #   "primary_endpoint": "https://partner.acme.com/api/login",
    #   "logout_endpoint": "https://partner.acme.com/logout",
    #   "redirect_chain": [...]
    # }
    endpoints: Mapped[dict[str, Any] | None] = Column(
        JSONB,
        nullable=True,
        comment="Primary auth endpoint and related URLs"
    )

    # Confidence and validation
    confidence_score: Mapped[int] = Column(Integer, nullable=False, default=100)
    success_count: Mapped[int] = Column(Integer, nullable=False, default=1)
    failure_count: Mapped[int] = Column(Integer, nullable=False, default=0)

    # Metadata
    learned_from_run_id: Mapped[str | None] = Column(String(36), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), nullable=False, index=True)
    last_successful_at: Mapped[datetime] = Column(DateTime(timezone=True), nullable=False)
    last_validated_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)

    # Additional context
    # Example: {
    #   "tech_stack": ["React", "WordPress"],
    #   "provider_hint": "okta",
    #   "observations": ["SPA framework detected"]
    # }
    context_data: Mapped[dict[str, Any] | None] = Column(
        "metadata",  # DB column name (can be 'metadata')
        JSONB,
        nullable=True,
        comment="Additional context: tech stack, provider hints, etc."
    )

    # Indexes defined in migration
    __table_args__ = (
        Index("idx_playbook_domain_profile", "domain", "profile_id"),
        Index("idx_playbook_domain_authtype", "domain", "auth_type"),
    )

    def calculate_confidence(self) -> int:
        """
        Calculate confidence score based on success/failure rate.

        Returns:
            Confidence score (0-100)
        """
        total_runs = self.success_count + self.failure_count
        if total_runs == 0:
            return 0

        success_rate = self.success_count / total_runs
        return int(success_rate * 100)

    def record_success(self, timestamp: datetime) -> None:
        """Record a successful authentication using this playbook."""
        self.success_count += 1
        self.last_successful_at = timestamp
        self.last_validated_at = timestamp
        self.confidence_score = self.calculate_confidence()

    def record_failure(self, timestamp: datetime) -> None:
        """Record a failed authentication using this playbook."""
        self.failure_count += 1
        self.last_validated_at = timestamp
        self.confidence_score = self.calculate_confidence()

    def is_reliable(self, threshold: int = 70) -> bool:
        """
        Check if this playbook is reliable enough to use deterministically.

        Args:
            threshold: Minimum confidence score to consider reliable

        Returns:
            True if confidence >= threshold
        """
        if self.confidence_score is None:
            return False
        return self.confidence_score >= threshold

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "domain": self.domain,
            "profile_id": self.profile_id,
            "auth_type": self.auth_type,
            "selectors": self.selectors,
            "endpoints": self.endpoints,
            "confidence_score": self.confidence_score,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "learned_from_run_id": self.learned_from_run_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_successful_at": self.last_successful_at.isoformat() if self.last_successful_at else None,
            "last_validated_at": self.last_validated_at.isoformat() if self.last_validated_at else None,
            "metadata": self.context_data,
        }
