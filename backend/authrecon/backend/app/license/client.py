"""
AuthRecon License Validation Client

Handles license activation, validation, and feature gating.

FAIL-SAFE MODE: Until LICENSE_VALIDATION_ENABLED=true, this module
allows all operations without license validation.
"""
import os
import json
import hashlib
import uuid
import socket
import logging
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict
from cryptography.fernet import Fernet
import httpx

logger = logging.getLogger(__name__)

# Fail-safe mode: Set to False until license server is deployed
LICENSE_VALIDATION_ENABLED = os.getenv("LICENSE_VALIDATION_ENABLED", "false").lower() == "true"

# License server URL
LICENSE_SERVER_URL = os.getenv("LICENSE_SERVER_URL", "https://license.authrecon.com")

# License file location
LICENSE_DIR = Path.home() / ".authrecon"
LICENSE_FILE = LICENSE_DIR / "license.json"


class LicenseValidationError(Exception):
    """Raised when license validation fails"""
    pass


class FeatureNotLicensedError(Exception):
    """Raised when attempting to use a feature not included in license"""
    pass


def _generate_machine_key() -> bytes:
    """
    Generate machine-specific encryption key for license file.
    Based on machine characteristics so license file can't be easily copied.
    """
    machine_uuid = str(uuid.getnode())
    hostname = socket.gethostname()
    combined = f"{machine_uuid}-{hostname}-authrecon-license"
    key_material = hashlib.sha256(combined.encode()).digest()
    # Fernet requires URL-safe base64-encoded 32-byte key
    return base64.urlsafe_b64encode(key_material)


def generate_installation_id() -> str:
    """
    Generate unique installation ID based on machine characteristics.
    Hashed to avoid exposing actual MAC address.
    """
    machine_uuid = uuid.getnode()  # MAC address
    hostname = socket.gethostname()

    # Hash to avoid exposing actual MAC address
    combined = f"{machine_uuid}-{hostname}"
    installation_id = hashlib.sha256(combined.encode()).hexdigest()[:32]

    return installation_id


def _load_license_file() -> Optional[Dict]:
    """Load and decrypt license file"""
    if not LICENSE_FILE.exists():
        return None

    try:
        with open(LICENSE_FILE, 'rb') as f:
            encrypted_data = f.read()

        # Decrypt
        fernet = Fernet(_generate_machine_key())
        decrypted_data = fernet.decrypt(encrypted_data)
        license_data = json.loads(decrypted_data)

        return license_data
    except Exception as e:
        logger.error(f"Error loading license file: {e}")
        return None


def _save_license_file(license_data: Dict):
    """Encrypt and save license file"""
    LICENSE_DIR.mkdir(parents=True, exist_ok=True)

    # Encrypt
    fernet = Fernet(_generate_machine_key())
    encrypted_data = fernet.encrypt(json.dumps(license_data).encode())

    with open(LICENSE_FILE, 'wb') as f:
        f.write(encrypted_data)

    logger.info("License file saved successfully")


def get_trial_license() -> Dict:
    """
    Generate 30-day trial license (local only, no server needed).

    Returns:
        Trial license data
    """
    trial_start = datetime.utcnow()
    trial_end = trial_start + timedelta(days=30)

    logger.info("Starting 30-day trial period")

    return {
        "valid": True,
        "license_type": "trial",
        "expires_at": trial_end.isoformat(),
        "trial_started": trial_start.isoformat(),
        "features": {
            "patterns": True,
            "ai_fallback": False,  # Trial gets patterns only
            "priority_support": False
        },
        "grace_period_days": 1,  # 1-day grace for trial
        "_trial_mode": True
    }


def activate_license(license_key: str, hostname: Optional[str] = None) -> Dict:
    """
    Activate a license key for this installation.

    Args:
        license_key: License key to activate
        hostname: Optional hostname for tracking

    Returns:
        License activation response

    Raises:
        LicenseValidationError: If activation fails
    """
    if not LICENSE_VALIDATION_ENABLED:
        logger.warning("⚠️  License validation is DISABLED (fail-safe mode)")
        logger.warning("   Set LICENSE_VALIDATION_ENABLED=true to enable")

        # Return mock response
        mock_response = {
            "valid": True,
            "license_type": "enterprise",  # Grant all features in dev mode
            "expires_at": (datetime.utcnow() + timedelta(days=365)).isoformat(),
            "features": {
                "patterns": True,
                "ai_fallback": True,
                "priority_support": True
            },
            "grace_period_days": 90,
            "next_check_in": (datetime.utcnow() + timedelta(days=7)).isoformat(),
            "_fail_safe_mode": True
        }

        _save_license_file({
            "license_key": license_key,
            "installation_id": generate_installation_id(),
            "last_validated": datetime.utcnow().isoformat(),
            **mock_response
        })

        return mock_response

    # Real activation
    installation_id = generate_installation_id()

    try:
        response = httpx.post(
            f"{LICENSE_SERVER_URL}/v1/activate",
            json={
                "license_key": license_key,
                "installation_id": installation_id,
                "version": "1.0.0",
                "hostname": hostname or socket.gethostname()
            },
            timeout=10.0
        )

        if response.status_code != 200:
            error_detail = response.json().get("detail", {})
            raise LicenseValidationError(
                error_detail.get("message", "License activation failed")
            )

        activation_data = response.json()

        # Save license locally
        license_data = {
            "license_key": license_key,
            "installation_id": installation_id,
            "last_validated": datetime.utcnow().isoformat(),
            **activation_data
        }
        _save_license_file(license_data)

        logger.info(f"License activated: {license_key[:20]}...")
        return activation_data

    except httpx.RequestError as e:
        raise LicenseValidationError(
            f"Could not connect to license server: {e}. "
            "Please check your internet connection."
        )


def check_license() -> Dict:
    """
    Periodic license validation check.

    Returns:
        License status

    Raises:
        LicenseValidationError: If validation fails
    """
    if not LICENSE_VALIDATION_ENABLED:
        logger.debug("License validation disabled (fail-safe mode)")
        return {
            "valid": True,
            "_fail_safe_mode": True
        }

    license_data = _load_license_file()
    if not license_data:
        # No license file = start 30-day trial automatically
        trial_license = get_trial_license()
        trial_license["installation_id"] = generate_installation_id()
        trial_license["last_validated"] = datetime.utcnow().isoformat()
        _save_license_file(trial_license)
        logger.info("🎉 Welcome to AuthRecon! 30-day trial started.")
        return trial_license

    # Check if this is a trial license
    if license_data.get("_trial_mode"):
        trial_started = datetime.fromisoformat(license_data["trial_started"])
        days_elapsed = (datetime.utcnow() - trial_started).days
        days_remaining = 30 - days_elapsed

        if days_elapsed > 30:
            raise LicenseValidationError(
                "⏰ 30-day trial expired.\n\n"
                "AuthRecon is free to use: set LICENSE_VALIDATION_ENABLED=false\n"
                "(the default) to run without license checks, or activate a key\n"
                "with: authrecon activate YOUR-LICENSE-KEY"
            )

        # Trial still valid
        logger.info(f"Trial license: {days_remaining} days remaining")
        return {
            "valid": True,
            "license_type": "trial",
            "days_remaining": days_remaining,
            "expires_at": license_data["expires_at"],
            "features": license_data.get("features", {}),
            "_trial_mode": True
        }

    last_validated = datetime.fromisoformat(license_data.get("last_validated"))
    grace_period_days = license_data.get("grace_period_days", 30)
    days_since_validation = (datetime.utcnow() - last_validated).days

    if days_since_validation < grace_period_days:
        # Still within grace period, use cached license
        logger.debug(f"License valid (cached), grace period: {grace_period_days - days_since_validation} days remaining")
        return {
            "valid": True,
            "expires_at": license_data.get("expires_at"),
            "grace_remaining_days": grace_period_days - days_since_validation,
            "_cached": True
        }

    # Grace period expired or time for periodic check - validate online
    try:
        response = httpx.post(
            f"{LICENSE_SERVER_URL}/v1/check",
            json={
                "license_key": license_data["license_key"],
                "installation_id": license_data["installation_id"],
                "version": "1.0.0"
            },
            timeout=10.0
        )

        if response.status_code != 200:
            error_detail = response.json().get("detail", {})

            # If grace period expired, raise error
            if days_since_validation >= grace_period_days:
                raise LicenseValidationError(
                    f"License validation failed and grace period expired. {error_detail.get('message', '')}"
                )

            # Still within grace, just warn
            logger.warning(f"License validation failed but within grace period: {error_detail.get('message')}")
            return {
                "valid": True,
                "grace_remaining_days": grace_period_days - days_since_validation,
                "_grace_mode": True
            }

        check_data = response.json()

        # Update last validated
        license_data["last_validated"] = datetime.utcnow().isoformat()
        _save_license_file(license_data)

        logger.info("License validated successfully")
        return check_data

    except httpx.RequestError as e:
        # Network error - use grace period
        if days_since_validation < grace_period_days:
            logger.warning(f"Could not connect to license server, using grace period: {e}")
            return {
                "valid": True,
                "grace_remaining_days": grace_period_days - days_since_validation,
                "_grace_mode": True
            }
        else:
            raise LicenseValidationError(
                f"License validation failed and grace period expired. "
                f"Please check your internet connection or contact support."
            )


def deactivate_license() -> Dict:
    """
    Deactivate license on this machine (to move to another machine).

    Returns:
        Deactivation response
    """
    if not LICENSE_VALIDATION_ENABLED:
        logger.warning("License validation disabled (fail-safe mode)")
        if LICENSE_FILE.exists():
            LICENSE_FILE.unlink()
        return {"success": True, "_fail_safe_mode": True}

    license_data = _load_license_file()
    if not license_data:
        raise LicenseValidationError("No license found to deactivate")

    try:
        response = httpx.post(
            f"{LICENSE_SERVER_URL}/v1/deactivate",
            json={
                "license_key": license_data["license_key"],
                "installation_id": license_data["installation_id"]
            },
            timeout=10.0
        )

        if response.status_code != 200:
            error_detail = response.json().get("detail", {})
            raise LicenseValidationError(
                error_detail.get("message", "Deactivation failed")
            )

        # Delete local license file
        if LICENSE_FILE.exists():
            LICENSE_FILE.unlink()

        logger.info("License deactivated successfully")
        return response.json()

    except httpx.RequestError as e:
        raise LicenseValidationError(
            f"Could not connect to license server: {e}"
        )


def get_license_info() -> Dict:
    """
    Get current license information (from local cache).

    Returns:
        License info or fail-safe status
    """
    if not LICENSE_VALIDATION_ENABLED:
        return {
            "valid": True,
            "license_type": "enterprise",
            "features": {
                "patterns": True,
                "ai_fallback": True,
                "priority_support": True
            },
            "_fail_safe_mode": True,
            "message": "License validation is DISABLED. Set LICENSE_VALIDATION_ENABLED=true to enable."
        }

    license_data = _load_license_file()
    if not license_data:
        return {
            "valid": False,
            "message": "No license activated. Run 'authrecon activate LICENSE-KEY'"
        }

    # Check if expired
    expires_at = datetime.fromisoformat(license_data.get("expires_at"))
    if expires_at < datetime.utcnow():
        return {
            "valid": False,
            "message": f"License expired on {expires_at.strftime('%Y-%m-%d')}. Please renew."
        }

    return {
        "valid": True,
        "license_type": license_data.get("license_type"),
        "expires_at": license_data.get("expires_at"),
        "features": license_data.get("features", {}),
        "last_validated": license_data.get("last_validated")
    }


def check_feature(feature_name: str) -> bool:
    """
    Check if a feature is enabled in current license.

    Args:
        feature_name: Feature to check (e.g., 'ai_fallback', 'priority_support')

    Returns:
        True if feature is enabled, False otherwise

    Raises:
        FeatureNotLicensedError: If license validation is enabled and feature not licensed
    """
    license_info = get_license_info()

    if not license_info.get("valid"):
        if LICENSE_VALIDATION_ENABLED:
            raise FeatureNotLicensedError(
                f"Feature '{feature_name}' requires a valid license. {license_info.get('message', '')}"
            )
        else:
            # Fail-safe mode: allow all features
            return True

    features = license_info.get("features", {})
    return features.get(feature_name, False)


def require_feature(feature_name: str, upgrade_message: str = None):
    """
    Decorator/function to require a specific feature.

    Args:
        feature_name: Required feature
        upgrade_message: Custom message about upgrading

    Raises:
        FeatureNotLicensedError: If feature not available
    """
    if not check_feature(feature_name):
        default_message = (
            f"Feature '{feature_name}' is not available in your license. "
            "Activate a key that includes it, or turn license validation off (the default)."
        )
        raise FeatureNotLicensedError(upgrade_message or default_message)
