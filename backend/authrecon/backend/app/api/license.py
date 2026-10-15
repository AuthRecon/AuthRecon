"""
License API endpoints

Connects frontend licensing UI to backend license validation system.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.deps import get_current_active_profile
from app.models.profile import AuthReconProfile
from typing import List, Optional
from datetime import datetime

from app.license.client import (
    get_license_info,
    check_license,
    generate_installation_id,
    LicenseValidationError,
    LICENSE_VALIDATION_ENABLED
)

router = APIRouter()


class LicenseStatusResponse(BaseModel):
    """License status for frontend UI"""
    valid: bool
    tier: str  # 'trial', 'basic', 'professional', 'enterprise'
    expiration: Optional[str] = None  # ISO 8601 timestamp
    installation_id: str
    features: List[str]  # Feature IDs
    last_checked: str  # ISO 8601 timestamp
    message: Optional[str] = None
    fail_safe_mode: bool = False


class LicenseCheckResponse(BaseModel):
    """License validation check result"""
    valid: bool
    message: str
    checked_at: str


def _map_features_to_frontend(backend_features: dict) -> List[str]:
    """
    Map backend feature flags to frontend feature IDs.

    Backend features: {"patterns": true, "ai_fallback": true, "priority_support": false}
    Frontend features: ["multi_role", "screenshot_export", "har_export", "side_export", "ai_analysis"]

    For now, map based on license tier:
    - Basic: core features only
    - Professional: all features except ai_analysis
    - Enterprise: all features
    """
    # Core features available in all licenses
    core_features = ["multi_role", "screenshot_export", "har_export", "side_export"]

    # AI features only in Professional/Enterprise
    if backend_features.get("ai_fallback", False):
        return core_features + ["ai_analysis"]

    return core_features


@router.get("/status", response_model=LicenseStatusResponse, summary="Get license status")
async def get_status(current_profile: AuthReconProfile = Depends(get_current_active_profile)) -> LicenseStatusResponse:
    """
    Get current license status for display in UI.

    Returns license tier, expiration, features, etc.
    Works in fail-safe mode (shows enterprise features) or real mode.
    """
    try:
        license_info = get_license_info()

        # Check if in fail-safe mode
        fail_safe = license_info.get("_fail_safe_mode", False)

        # Map backend data to frontend format
        return LicenseStatusResponse(
            valid=license_info.get("valid", False),
            tier=license_info.get("license_type", "unknown"),
            expiration=license_info.get("expires_at"),
            installation_id=generate_installation_id(),
            features=_map_features_to_frontend(license_info.get("features", {})),
            last_checked=license_info.get("last_validated", datetime.utcnow().isoformat()),
            message=license_info.get("message",
                "License validation enabled" if LICENSE_VALIDATION_ENABLED
                else "Fail-safe mode: all features enabled"
            ),
            fail_safe_mode=fail_safe
        )

    except Exception as e:
        # If license system has issues, return safe defaults in dev mode
        if not LICENSE_VALIDATION_ENABLED:
            return LicenseStatusResponse(
                valid=True,
                tier="enterprise",
                expiration=(datetime.utcnow().replace(year=datetime.utcnow().year + 1)).isoformat(),
                installation_id=generate_installation_id(),
                features=["multi_role", "screenshot_export", "har_export", "side_export", "ai_analysis"],
                last_checked=datetime.utcnow().isoformat(),
                message="Fail-safe mode: license validation disabled",
                fail_safe_mode=True
            )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving license status: {str(e)}"
        )


@router.post("/check", response_model=LicenseCheckResponse, summary="Validate license")
async def check(current_profile: AuthReconProfile = Depends(get_current_active_profile)) -> LicenseCheckResponse:
    """
    Perform license validation check with license server.

    Triggered by "Refresh status" button in UI.
    """
    try:
        result = check_license()

        if result.get("_fail_safe_mode"):
            return LicenseCheckResponse(
                valid=True,
                message="Fail-safe mode: license validation disabled",
                checked_at=datetime.utcnow().isoformat()
            )

        if result.get("_cached"):
            return LicenseCheckResponse(
                valid=True,
                message=f"License valid (cached). Grace period: {result.get('grace_remaining_days')} days remaining.",
                checked_at=datetime.utcnow().isoformat()
            )

        if result.get("_grace_mode"):
            return LicenseCheckResponse(
                valid=True,
                message=f"License validation failed but within grace period ({result.get('grace_remaining_days')} days remaining)",
                checked_at=datetime.utcnow().isoformat()
            )

        return LicenseCheckResponse(
            valid=result.get("valid", False),
            message=result.get("message", "License validated successfully"),
            checked_at=datetime.utcnow().isoformat()
        )

    except LicenseValidationError as e:
        # License validation failed
        return LicenseCheckResponse(
            valid=False,
            message=str(e),
            checked_at=datetime.utcnow().isoformat()
        )

    except Exception as e:
        if not LICENSE_VALIDATION_ENABLED:
            return LicenseCheckResponse(
                valid=True,
                message="Fail-safe mode: license validation disabled",
                checked_at=datetime.utcnow().isoformat()
            )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking license: {str(e)}"
        )
