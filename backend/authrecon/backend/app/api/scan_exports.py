"""Tenable WAS scan exports for the scan analyzer (SCAFFOLD).

The analyzer is MCP-only: users upload a WAS export zip here, and an AI client
connected over MCP reads the parsed summary through allow-listed tools to help
fix scan problems. Every route enforces owner-or-admin. No route returns the
raw zip (it can contain scan credentials); clients only get metadata and the
parser's summary.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_profile
from app.db import get_db
from app.models.profile import AuthReconProfile
from app.models.scan_export import ScanExport
from app.services.artifact_crypto import write_key_for_profile
from app.services.scan_export_parser import MAX_UPLOAD_BYTES, ScanExportError, parse_export
from app.services.storage import get_artifact_storage

router = APIRouter(prefix="/scan-exports", tags=["scan-analyzer"])


class ScanExportOut(BaseModel):
    id: str
    filename: str
    size_bytes: int
    sha256: str
    status: str
    summary: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime
    parsed_at: datetime | None = None
    owner_profile_id: str

    class Config:
        orm_mode = True


def _storage_namespace(export_id: str) -> str:
    return f"scan-export-{export_id}"


def _get_for_user(db: Session, export_id: str, profile: AuthReconProfile) -> ScanExport:
    export = db.get(ScanExport, export_id)
    if export is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan export not found")
    if not getattr(profile, "is_admin", False) and export.owner_profile_id != profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")
    return export


def _safe_filename(name: str | None) -> str:
    base = (name or "export.zip").replace("\\", "/").rsplit("/", 1)[-1]
    return re.sub(r"[^A-Za-z0-9._ -]", "_", base)[:200] or "export.zip"


@router.post("", response_model=ScanExportOut, status_code=status.HTTP_201_CREATED, summary="Upload a WAS scan export")
async def upload_scan_export(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> ScanExport:
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    try:
        parsed = parse_export(data)
    except ScanExportError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None

    export_id = str(uuid4())
    namespace = _storage_namespace(export_id)
    storage = get_artifact_storage()
    storage.bind_run_key(namespace, write_key_for_profile(db, current_profile))
    db.commit()  # persist a freshly provisioned artifact key before anything depends on it
    try:
        path = storage.save_bytes(namespace, "export.zip", data)
    finally:
        storage.release_run(namespace)

    export = ScanExport(
        id=export_id,
        owner_profile_id=current_profile.id,
        filename=_safe_filename(file.filename),
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        storage_path=path,
        status="parsed",
        summary=parsed.summary,
        parsed_at=datetime.now(timezone.utc),
    )
    db.add(export)
    db.commit()
    db.refresh(export)
    return export


@router.get("", response_model=list[ScanExportOut], summary="List your scan exports")
def list_scan_exports(
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> list[ScanExport]:
    stmt = select(ScanExport).order_by(ScanExport.created_at.desc())
    if not getattr(current_profile, "is_admin", False):
        stmt = stmt.where(ScanExport.owner_profile_id == current_profile.id)
    return list(db.scalars(stmt).all())


@router.get("/{export_id}", response_model=ScanExportOut, summary="Get a scan export's summary")
def get_scan_export(
    export_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> ScanExport:
    return _get_for_user(db, export_id, current_profile)


@router.delete("/{export_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a scan export")
def delete_scan_export(
    export_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> Response:
    export = _get_for_user(db, export_id, current_profile)
    get_artifact_storage().delete_run(_storage_namespace(export.id))
    db.delete(export)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
