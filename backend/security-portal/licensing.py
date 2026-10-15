"""Lightweight licensing scaffold for AuthRecon."""
from __future__ import annotations

import hashlib
import json
import platform
import socket
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from config import PortalConfig

DEFAULT_FEATURES = [
    "multi_role",
    "screenshot_export",
    "har_export",
    "side_export",
    "ai_analysis",
]


@dataclass
class LicenseStatus:
    valid: bool = True
    tier: str = "enterprise"
    expiration: Optional[str] = None
    installation_id: str = ""
    license_key: Optional[str] = None
    features: List[str] = field(default_factory=lambda: DEFAULT_FEATURES.copy())
    last_checked: str = datetime.utcnow().isoformat()
    message: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class LicenseManager:
    """Placeholder licensing manager that always treats license as valid."""

    def __init__(self, config: PortalConfig):
        self.config = config
        self.cache_path: Path = config.license_cache_path
        self.status: LicenseStatus = self._load_cached_status() or self._generate_placeholder_status()
        if not self.status.installation_id:
            self.status.installation_id = self._generate_installation_id()
            self._persist()

    # Public API
    def get_status(self) -> LicenseStatus:
        # Check if trial expired
        if self.status.tier == "trial" and self.status.expiration:
            expiration = datetime.fromisoformat(self.status.expiration)
            if datetime.utcnow() > expiration:
                self.status.valid = False
                self.status.message = "30-day trial expired. Contact sales for a license."
        return self.status

    def refresh(self, license_key: Optional[str] = None) -> LicenseStatus:
        """Revalidate with placeholder response (local-only for now)."""
        self.status = self._generate_placeholder_status(license_key=license_key)
        self._persist()
        return self.status

    def is_feature_enabled(self, feature: str) -> bool:
        if not self.status.valid:
            return False
        if not self.status.features:
            return True
        return feature in self.status.features

    # Internal helpers
    def _load_cached_status(self) -> Optional[LicenseStatus]:
        if not self.cache_path.exists():
            return None
        try:
            data = json.loads(self.cache_path.read_text())
            return LicenseStatus(**data)
        except Exception:
            return None

    def _persist(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self.status.to_dict(), indent=2))
        except Exception:
            pass

    def _generate_installation_id(self) -> str:
        host = platform.node() or socket.gethostname()
        mac = uuid.getnode()
        raw = f"{host}-{mac}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _generate_placeholder_status(self, license_key: Optional[str] = None) -> LicenseStatus:
        installation_id = self.status.installation_id if hasattr(self, "status") else self._generate_installation_id()

        # Check if we're validating licenses
        validation_enabled = self.config.license_validation_enabled if hasattr(self.config, 'license_validation_enabled') else False

        if validation_enabled and not license_key:
            # Start 30-day trial
            trial_start = datetime.utcnow()
            trial_end = trial_start + timedelta(days=30)
            return LicenseStatus(
                valid=True,
                tier="trial",
                expiration=trial_end.isoformat(),
                installation_id=installation_id,
                license_key="TRIAL-30-DAY",
                features=["multi_role", "screenshot_export", "har_export", "side_export"],  # Trial: no AI
                last_checked=trial_start.isoformat(),
                message=f"30-day trial started. Expires: {trial_end.strftime('%Y-%m-%d')}",
            )

        # Open-source build: all features unlocked, perpetually free.
        # (The trial/validation branch above is kept intact so a licensing
        # regime can be re-enabled later by setting license_validation_enabled.)
        return LicenseStatus(
            valid=True,
            tier="Open Source",
            expiration=None,  # perpetual — never expires
            installation_id=installation_id,
            license_key=license_key or "OPEN-SOURCE",
            features=DEFAULT_FEATURES.copy(),
            last_checked=datetime.utcnow().isoformat(),
            message="Free & open source — all features included.",
        )


def license_feature_required(feature: str):
    """Decorator factory for FastAPI endpoints once enforcement is needed."""

    def dependency(request):
        manager: LicenseManager = request.app.state.license_manager
        status = manager.get_status()
        if not status.valid or not manager.is_feature_enabled(feature):
            from fastapi import HTTPException

            raise HTTPException(status_code=403, detail="Feature not enabled by current license")
        return True

    return dependency
