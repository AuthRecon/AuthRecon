"""Simple Fernet-based encryption helpers for the portal."""
from __future__ import annotations

import logging
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

LOGGER = logging.getLogger("PortalEncryption")


class EncryptionManager:
    """Wrapper around a Fernet key.

    Prefer ``from_key_bytes()`` for new deployments (key comes from an env var or
    secret manager and never touches the filesystem).  The ``__init__`` path
    (key loaded from a file) remains supported for existing installs.
    """

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        self._fernet = Fernet(self._read_key())

    @classmethod
    def from_key_bytes(cls, key: bytes) -> "EncryptionManager":
        """Build an EncryptionManager directly from raw key bytes.

        Use this when the key arrives via an environment variable or secret manager
        instead of a file on disk.  The key must be a URL-safe base64-encoded
        32-byte Fernet key (i.e., the raw bytes after decoding PORTAL_ENCRYPTION_KEY).
        """
        instance = cls.__new__(cls)
        instance.key_path = None
        try:
            instance._fernet = Fernet(key)
        except Exception as exc:
            raise RuntimeError(
                "PORTAL_ENCRYPTION_KEY is not a valid Fernet key. "
                "Generate one with: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            ) from exc
        return instance

    def encrypt(self, value: str) -> str:
        """Encrypt a unicode string and return a token."""
        token = self._fernet.encrypt(value.encode("utf-8"))
        return token.decode("utf-8")

    def encrypt_blob(self, payload: bytes) -> bytes:
        """Encrypt raw bytes (used for artifacts)."""
        return self._fernet.encrypt(payload)

    def decrypt(self, token: str) -> str:
        """Decrypt a token that was produced by :meth:`encrypt`."""
        data = self._fernet.decrypt(token.encode("utf-8"))
        return data.decode("utf-8")

    def decrypt_blob(self, token: bytes) -> bytes:
        return self._fernet.decrypt(token)

    def decrypt_if_encrypted(self, value: str) -> tuple[str, bool]:
        """Attempt to decrypt ``value``; return (plaintext, was_encrypted)."""
        try:
            plaintext = self.decrypt(value)
            return plaintext, True
        except InvalidToken:
            return value, False

    def ensure_encrypted(self, value: str) -> tuple[str, bool]:
        """Return an encrypted token, encrypting if the value was plaintext."""
        plaintext, already = self.decrypt_if_encrypted(value)
        if already:
            return value, False
        return self.encrypt(plaintext), True

    def _read_key(self) -> bytes:
        if not self.key_path.exists():
            raise RuntimeError(
                f"Portal encryption key missing at {self.key_path}. Generate it before starting the portal."
            )
        key = self.key_path.read_bytes().strip()
        try:
            # Validate the key by instantiating Fernet once.
            Fernet(key)
        except Exception as exc:  # pragma: no cover - defensive programming
            raise RuntimeError(f"Invalid portal encryption key at {self.key_path}") from exc
        return key


def ensure_key_exists(path: Path) -> None:
    """Create a new Fernet key at ``path`` if it does not already exist."""
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    path.write_bytes(key)
    path.chmod(0o600)
    LOGGER.info("Generated new portal encryption key at %s", path)
