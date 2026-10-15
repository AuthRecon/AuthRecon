"""Encrypted artifact persistence helpers."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from typing import Callable, Dict, Optional

from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from models.artifact import PortalArtifact
from security.encryption import EncryptionManager


class ArtifactStore:
    """Write/read encrypted artifacts for portal modules."""

    def __init__(self, session_factory: Callable[[], Session], encryptor: EncryptionManager) -> None:
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

    def create(
        self,
        *,
        asset_id: str | None,
        owner_id: str | None,
        sharing_scope: str,
        module: str,
        artifact_type: str,
        summary: str | None,
        metadata: Dict,
        blob: bytes | str,
    ) -> PortalArtifact:
        if isinstance(blob, str):
            encrypted_blob = self._encryptor.encrypt(blob).encode("utf-8")
        else:
            encrypted_blob = self._encryptor.encrypt_blob(blob)
        with self._session() as session:
            record = PortalArtifact(
                asset_id=asset_id,
                owner_id=owner_id,
                sharing_scope=sharing_scope,
                module=module,
                artifact_type=artifact_type,
                summary=summary,
                details=metadata,
                encrypted_blob=encrypted_blob,
                created_at=datetime.utcnow(),
            )
            session.add(record)
            return record

    def fetch(self, artifact_id: str) -> Optional[Dict[str, object]]:
        with self._session() as session:
            record = session.scalar(select(PortalArtifact).where(PortalArtifact.id == artifact_id).limit(1))
            if not record:
                return None
            blob_bytes = self._encryptor.decrypt_blob(record.encrypted_blob)
            try:
                blob_value: bytes | str = blob_bytes.decode("utf-8")
            except UnicodeDecodeError:
                blob_value = blob_bytes
            return {
                "id": record.id,
                "asset_id": record.asset_id,
                "owner_id": record.owner_id,
                "sharing_scope": record.sharing_scope,
                "module": record.module,
                "artifact_type": record.artifact_type,
                "summary": record.summary,
                "metadata": record.details,
                "blob": blob_value,
                "created_at": record.created_at,
            }

    def list_recent(
        self,
        *,
        module: str,
        owner_key: str | None,
        include_private: bool,
        limit: int = 20,
    ) -> list[PortalArtifact]:
        with self._session() as session:
            stmt = (
                select(PortalArtifact)
                .where(PortalArtifact.module == module)
                .order_by(desc(PortalArtifact.created_at))
                .limit(limit * 2)
            )
            rows = session.scalars(stmt).all()
            filtered: list[PortalArtifact] = []
            for row in rows:
                if row.sharing_scope == "global":
                    filtered.append(row)
                elif row.sharing_scope == "private":
                    if include_private and owner_key and row.owner_id == owner_key:
                        filtered.append(row)
                else:
                    filtered.append(row)
                if len(filtered) >= limit:
                    break
            return filtered
