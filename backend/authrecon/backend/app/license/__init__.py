"""
Standalone License CLI

This module is separate from the main FastAPI app so it can run
without loading FastAPI dependencies.
"""
from .client import (
    activate_license,
    check_license,
    deactivate_license,
    get_license_info,
    generate_installation_id,
    check_feature,
    require_feature,
    LICENSE_VALIDATION_ENABLED,
    LicenseValidationError,
    FeatureNotLicensedError
)

__all__ = [
    "activate_license",
    "check_license",
    "deactivate_license",
    "get_license_info",
    "generate_installation_id",
    "check_feature",
    "require_feature",
    "LICENSE_VALIDATION_ENABLED",
    "LicenseValidationError",
    "FeatureNotLicensedError"
]
