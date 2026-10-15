"""Database-backed configuration store for Tenable/LLM settings."""
from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from typing import Any, Callable, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.setting import PortalSetting
from security.encryption import EncryptionManager

LOGGER = logging.getLogger("PortalConfigStore")


class ConfigStore:
    """Persist arbitrary JSON blobs keyed by identifier."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        encryptor: EncryptionManager | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._encryptor = encryptor

    @contextmanager
    def _session(self) -> Session:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save(self, key: str, data: Dict[str, Any]) -> None:
        serialized = json.dumps(data)
        if self._encryptor:
            serialized = self._encryptor.encrypt(serialized)
        with self._session() as session:
            setting = session.get(PortalSetting, key)
            if setting:
                setting.value = serialized
            else:
                session.add(PortalSetting(key=key, value=serialized))

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._session() as session:
            setting = session.scalar(select(PortalSetting).where(PortalSetting.key == key).limit(1))
            if not setting:
                return None
            try:
                payload = setting.value
                if self._encryptor:
                    plaintext, _ = self._encryptor.decrypt_if_encrypted(payload)
                else:
                    plaintext = payload
                return json.loads(plaintext)
            except json.JSONDecodeError:
                return None

    def migrate_plaintext(self) -> int:
        """Encrypt legacy plaintext rows, returning the count of updated settings."""
        if not self._encryptor:
            return 0
        updated = 0
        with self._session() as session:
            rows = session.scalars(select(PortalSetting)).all()
            for row in rows:
                _, already = self._encryptor.decrypt_if_encrypted(row.value)
                if already:
                    continue
                row.value = self._encryptor.encrypt(row.value)
                updated += 1
        if updated:
            LOGGER.info("Re-encrypted %d portal settings", updated)
        return updated
