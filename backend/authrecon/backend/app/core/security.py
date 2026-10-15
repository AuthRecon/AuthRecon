from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet

from app.core.config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(subject: str, expires_minutes: int | None = None, extra_claims: Dict[str, Any] | None = None) -> str:
    settings = get_settings()
    expires = expires_minutes or settings.access_token_expire_minutes
    expire_at = datetime.now(timezone.utc) + timedelta(minutes=expires)
    to_encode: Dict[str, Any] = {"sub": subject, "exp": expire_at}
    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise ValueError("Invalid token") from exc


def hash_password(password: str) -> str:
    trimmed = password[:72]
    return pwd_context.hash(trimmed)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    trimmed = plain_password[:72]
    return pwd_context.verify(trimmed, hashed_password)


_fernet: Fernet | None = None


def _derive_fernet_key(source: str) -> bytes:
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def get_credential_cipher() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    settings = get_settings()
    if settings.credential_encryption_key:
        key_source = settings.credential_encryption_key
    else:
        key_source = settings.secret_key
    key = _derive_fernet_key(key_source)
    _fernet = Fernet(key)
    return _fernet


def encrypt_with_master(data: bytes) -> str:
    """
    Encrypt arbitrary bytes with the application master key (same key used for stored credentials).
    Returned value is safe to persist as text.
    """
    cipher = get_credential_cipher()
    return cipher.encrypt(data).decode("utf-8")


def decrypt_with_master(token: str) -> bytes:
    """
    Decrypt data previously encrypted with encrypt_with_master.
    """
    cipher = get_credential_cipher()
    return cipher.decrypt(token.encode("utf-8"))


# ============================================================================
# API Key Management (for CLI authentication)
# ============================================================================


def generate_api_key() -> str:
    """
    Generate a cryptographically secure API key.

    Format: ak_live_<32 random chars>
    - ak_ = API Key prefix
    - live_ = Environment identifier
    - 32 chars = ~190 bits of entropy (URL-safe base64)

    Returns:
        str: API key in format ak_live_xxxxxxxxxxxxxxxxxxxxxxxx

    Example:
        >>> key = generate_api_key()
        >>> print(key)
        'ak_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    """
    # Generate 24 random bytes (32 chars when base64-encoded)
    random_bytes = secrets.token_bytes(24)
    # URL-safe base64 encoding (no padding needed)
    random_str = base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=")

    return f"ak_live_{random_str}"


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using bcrypt (same as passwords).

    Args:
        api_key: Plaintext API key (e.g., ak_live_xxxxx)

    Returns:
        str: bcrypt hash of the API key

    Security:
        - Uses bcrypt with automatic salt generation
        - Cost factor inherited from pwd_context
        - Same security level as password hashing
    """
    return pwd_context.hash(api_key)


def verify_api_key(plaintext_key: str, hashed_key: str) -> bool:
    """
    Verify a plaintext API key against its bcrypt hash.

    Args:
        plaintext_key: API key provided by client (e.g., ak_live_xxxxx)
        hashed_key: bcrypt hash stored in database

    Returns:
        bool: True if key matches, False otherwise

    Security:
        - Constant-time comparison (via bcrypt)
        - No timing attack vulnerability
    """
    try:
        return pwd_context.verify(plaintext_key, hashed_key)
    except Exception:
        # Invalid hash format or verification error
        return False


def create_api_key_prefix(api_key: str) -> str:
    """
    Create a display-safe prefix for an API key.

    Shows first 3 chars and last 4 chars for identification.
    Format: ak_...xJ7k

    Args:
        api_key: Full API key (e.g., ak_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)

    Returns:
        str: Display prefix (e.g., ak_...xJ7k)

    Example:
        >>> key = "ak_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        >>> prefix = create_api_key_prefix(key)
        >>> print(prefix)
        'ak_...E0fG'
    """
    if len(api_key) < 12:
        # Key too short, just show first few chars
        return f"{api_key[:5]}..."

    # Show first 3 chars (ak_) and last 4 chars
    return f"{api_key[:3]}...{api_key[-4:]}"
