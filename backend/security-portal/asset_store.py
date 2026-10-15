"""Resolver/helpers for the portal asset catalog."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from models.asset import PortalAsset

LOGGER = logging.getLogger("PortalAssetStore")


class AssetStore:
    """High-level helpers for creating/fetching portal assets."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

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

    def resolve(
        self,
        *,
        owner_id: str | None = None,
        sharing_scope: str = "global",
        canonical_name: str | None = None,
        primary_ip: str | None = None,
        identifiers: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
        source: str | None = None,
    ) -> PortalAsset:
        """Return an existing asset or create a new one based on identifiers."""

        normalized_ids = _normalize_values(identifiers or [])
        normalized_name = _normalize_single(canonical_name)
        normalized_ip = primary_ip.strip() if primary_ip else None

        with self._session() as session:
            asset = self._lookup(session, normalized_name, normalized_ip, normalized_ids, owner_id)
            if asset:
                asset.last_seen = datetime.utcnow()
                asset.updated_at = datetime.utcnow()
                asset.tags = _merge_lists(asset.tags or [], tags or [])
                asset.alt_identifiers = _merge_maps(asset.alt_identifiers or {}, {"ids": normalized_ids})
                session.flush()
                return asset

            payload = PortalAsset(
                owner_id=owner_id,
                sharing_scope=sharing_scope,
                canonical_name=normalized_name,
                primary_ip=normalized_ip,
                alt_identifiers={"ids": normalized_ids},
                tags=list(tags or []),
                source=source,
                last_seen=datetime.utcnow(),
            )
            session.add(payload)
            session.flush()
            LOGGER.info("Created new asset %s (%s)", payload.id, payload.canonical_name or payload.primary_ip)
            return payload

    def _lookup(
        self,
        session: Session,
        name: Optional[str],
        ip: Optional[str],
        identifiers: list[str],
        owner_id: Optional[str],
    ) -> Optional[PortalAsset]:
        filters = []
        if name:
            filters.append(func.lower(PortalAsset.canonical_name) == name)
        if ip:
            filters.append(PortalAsset.primary_ip == ip)
        if owner_id:
            filters.append(PortalAsset.owner_id == owner_id)

        if filters:
            stmt = select(PortalAsset).where(or_(*filters)).limit(1)
            match = session.scalar(stmt)
            if match:
                return match

        if identifiers:
            rows = session.scalars(select(PortalAsset)).all()
            for row in rows:
                ids = (row.alt_identifiers or {}).get("ids", [])
                if any(identifier in ids for identifier in identifiers):
                    return row
        return None


def _normalize_single(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return value.strip().lower()


def _normalize_values(values: Iterable[str]) -> list[str]:
    normalized = []
    for value in values:
        cleaned = _normalize_single(value)
        if cleaned:
            normalized.append(cleaned)
    return normalized


def _merge_lists(current: list[str], new_values: Iterable[str]) -> list[str]:
    combined = list(current)
    for value in new_values:
        if value not in combined:
            combined.append(value)
    return combined


def _merge_maps(current: Dict[str, Any], addition: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(current)
    for key, value in addition.items():
        if isinstance(value, list):
            merged[key] = _merge_lists(merged.get(key, []), value)
        else:
            merged[key] = value
    return merged
