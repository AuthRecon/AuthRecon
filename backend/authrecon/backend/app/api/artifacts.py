import json
import os
import re
import zipfile
from datetime import datetime, timezone
from io import BytesIO

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_profile
from app.db import get_db
from app.models import Artifact as ArtifactModel, Run
from app.models.profile import AuthReconProfile
from app.schemas.artifact import Artifact, ArtifactType

# Stored types of the per-tool export files (worker.py); shown as one group.
_SCANNER_IMPORT_TYPES = {"burp_request", "curl_script", "postman_collection", "zap_context"}
from app.services.artifact_links import build_placeholder_url
from app.services.storage import get_artifact_storage
from app.services.artifact_crypto import ArtifactDecryptError, read_artifact_bytes

router = APIRouter()


@router.get(
    "/{run_id}/artifacts",
    response_model=list[Artifact],
    summary="List artifacts for a run"
)
async def list_artifacts(
    request: Request,
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> list[Artifact]:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")

    records = db.scalars(
        select(ArtifactModel).where(ArtifactModel.run_id == run_id).order_by(ArtifactModel.created_at.asc())
    ).all()

    if not records:
        # Placeholder data until workers begin writing artifacts
        return []

    response: list[Artifact] = []
    role_map, _ = _load_role_scope(run)
    for record in records:
        try:
            artifact_type = ArtifactType(record.type)
        except ValueError:
            artifact_type = (
                ArtifactType.scanner_import if record.type in _SCANNER_IMPORT_TYPES else ArtifactType.log
            )

        download_url: str | None = record.download_url
        if not download_url and record.storage_path and request is not None:
            try:
                download_url = str(
                    request.url_for(
                        "download_artifact",
                        run_id=run_id,
                        artifact_id=record.id,
                    )
                )
            except Exception:  # pragma: no cover - defensive for URL building
                download_url = None

        if not download_url:
            download_url = str(build_placeholder_url(record.run_id, record.name))

        role_slug = record.role_slug or _artifact_role_slug(record, run_id, role_map)
        role_label = None
        if role_slug and role_map.get(role_slug):
            role_label = role_map[role_slug].get("label")

        response.append(
            Artifact(
                id=record.id,
                run_id=record.run_id,
                name=record.name,
                description=record.description,
                type=artifact_type,
                size_bytes=record.size_bytes,
                created_at=record.created_at,
                download_url=download_url,
                is_encrypted=bool(record.is_encrypted),
                role_slug=role_slug,
                role_label=role_label,
            )
        )

    return response


@router.get(
    "/{run_id}/har",
    summary="Get HAR file content for HTTP flow viewer",
)
async def get_har_file(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> dict:
    """
    Retrieve HAR file content as JSON for DevTools-style HTTP flow viewer.

    Returns the parsed HAR file for displaying requests/responses.
    """
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")

    # Find HAR artifact (get the most recent if multiple exist)
    har_artifact = db.execute(
        select(ArtifactModel)
        .where(
            ArtifactModel.run_id == run_id,
            ArtifactModel.type == "har",
        )
        .order_by(ArtifactModel.created_at.desc())
    ).scalars().first()

    if not har_artifact or not har_artifact.storage_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="HAR file not available")

    try:
        payload, _ = _read_artifact_bytes(db, run, har_artifact, get_artifact_storage())
        # Parse HAR file as JSON
        har_data = json.loads(payload.decode('utf-8'))
        return har_data
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="HAR file missing") from None
    except json.JSONDecodeError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Invalid HAR file format") from None


@router.get(
    "/{run_id}/artifacts/{artifact_id}/download",
    name="download_artifact",
    summary="Download an artifact file",
)
async def download_artifact(
    run_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> Response:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")

    artifact = db.execute(
        select(ArtifactModel).where(
            ArtifactModel.id == artifact_id,
            ArtifactModel.run_id == run_id,
        )
    ).scalar_one_or_none()

    if not artifact or not artifact.storage_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not available")

    try:
        payload, filename = _read_artifact_bytes(db, run, artifact, get_artifact_storage())
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact file missing") from None
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=payload, media_type="application/octet-stream", headers=headers)


@router.get(
    "/{run_id}/artifacts/download-all",
    summary="Download all artifacts for a run as a ZIP archive",
)
async def download_all_artifacts(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> Response:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")

    records = db.scalars(
        select(ArtifactModel).where(ArtifactModel.run_id == run_id).order_by(ArtifactModel.created_at.asc())
    ).all()

    if not records:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No artifacts for this run")

    storage = get_artifact_storage()
    zip_buffer = BytesIO()
    added = 0
    existing_paths: set[str] = set()
    role_map, multi_role = _load_role_scope(run)
    artifact_counts: dict[str, int] = {slug: 0 for slug in role_map}
    shared_count = 0
    timestamp = datetime.now(timezone.utc).isoformat()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            if not record.storage_path:
                continue
            try:
                payload, filename = _read_artifact_bytes(db, run, record, storage)
            except FileNotFoundError:
                continue
            slug = (record.role_slug or _artifact_role_slug(record, run_id, role_map)) if multi_role else None
            folder = f"{slug}/" if slug else ("shared/" if multi_role else "")
            safe_name = _sanitize_filename(filename)
            if slug:
                safe_name = _strip_role_prefix(safe_name, slug)
            else:
                shared_count += 1
            archive_path = _unique_archive_name(f"{folder}{safe_name}", existing_paths)
            archive.writestr(archive_path, payload)
            if slug:
                artifact_counts[slug] = artifact_counts.get(slug, 0) + 1
            added += 1

        if role_map:
            for slug, info in role_map.items():
                metadata = _build_role_metadata(run_id, slug, info, artifact_counts.get(slug, 0), timestamp)
                archive.writestr(f"{slug}/metadata.json", json.dumps(metadata, indent=2))
        manifest = _build_manifest(run_id, timestamp, role_map, artifact_counts, shared_count)
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))

    if not added:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifacts unavailable for download")

    zip_buffer.seek(0)
    bundle_name = f"{run_id}_artifacts.zip"
    headers = {"Content-Disposition": f'attachment; filename="{bundle_name}"'}
    return Response(content=zip_buffer.getvalue(), media_type="application/zip", headers=headers)


@router.get(
    "/{run_id}/artifacts/roles/{role_slug}/download",
    summary="Download artifacts for a specific role",
)
async def download_role_artifacts(
    run_id: str,
    role_slug: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> Response:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")

    role_map, multi_role = _load_role_scope(run)
    if not multi_role or role_slug not in role_map:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found for run")

    records = db.scalars(
        select(ArtifactModel)
        .where(ArtifactModel.run_id == run_id, ArtifactModel.role_slug == role_slug)
        .order_by(ArtifactModel.created_at.asc())
    ).all()

    if not records:
        legacy_records = db.scalars(
            select(ArtifactModel).where(ArtifactModel.run_id == run_id).order_by(ArtifactModel.created_at.asc())
        ).all()
        records = [
            record for record in legacy_records if _artifact_role_slug(record, run_id, role_map) == role_slug
        ]

    if not records:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No artifacts for this run")

    storage = get_artifact_storage()
    zip_buffer = BytesIO()
    existing_paths: set[str] = set()
    added = 0
    timestamp = datetime.now(timezone.utc).isoformat()
    role_info = role_map[role_slug]
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            slug = record.role_slug or _artifact_role_slug(record, run_id, role_map)
            if slug != role_slug or not record.storage_path:
                continue
            try:
                payload, filename = _read_artifact_bytes(db, run, record, storage)
            except FileNotFoundError:
                continue
            folder = f"{role_slug}/"
            safe_name = _strip_role_prefix(_sanitize_filename(filename), role_slug)
            archive_path = _unique_archive_name(f"{folder}{safe_name}", existing_paths)
            archive.writestr(archive_path, payload)
            added += 1
        metadata = _build_role_metadata(run_id, role_slug, role_info, added, timestamp)
        archive.writestr(f"{role_slug}/metadata.json", json.dumps(metadata, indent=2))

    if not added:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No artifacts were captured for this role")

    zip_buffer.seek(0)
    bundle_name = f"{run_id}_{role_slug}_artifacts.zip"
    headers = {"Content-Disposition": f'attachment; filename="{bundle_name}"'}
    return Response(content=zip_buffer.getvalue(), media_type="application/zip", headers=headers)


def _read_artifact_bytes(
    db: Session,
    run: Run,
    artifact: ArtifactModel,
    storage,
) -> tuple[bytes, str]:
    """Decrypt an artifact for an already-authorized (owner-or-admin) caller."""
    try:
        payload = read_artifact_bytes(db, run, artifact, storage)
    except ArtifactDecryptError as exc:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Encrypted artifact cannot be decrypted (owner key unavailable).",
        ) from exc
    filename = artifact.name or f"{artifact.id}.bin"
    return payload, filename


def _sanitize_filename(name: str) -> str:
    base = os.path.basename(name or "").strip() or "artifact"
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return sanitized or "artifact"


def _unique_archive_name(path: str, existing: set[str]) -> str:
    candidate = path
    if candidate not in existing:
        existing.add(candidate)
        return candidate
    folder, filename = os.path.split(path)
    base, ext = os.path.splitext(filename)
    counter = 1
    while True:
        new_name = f"{base}_{counter}{ext}"
        candidate = os.path.join(folder, new_name) if folder else new_name
        if candidate not in existing:
            existing.add(candidate)
            return candidate
        counter += 1


def _load_role_scope(run: Run) -> tuple[dict[str, dict], bool]:
    options = run.options if isinstance(run.options, dict) else {}
    raw_scope = options.get("scope") if isinstance(options, dict) else {}
    role_map: dict[str, dict] = {}
    multi_role = False
    if isinstance(raw_scope, dict):
        roles = raw_scope.get("roles")
        if isinstance(roles, list) and roles:
            multi_role = True
            for entry in roles:
                if not isinstance(entry, dict):
                    continue
                slug = entry.get("slug")
                if slug:
                    role_map[str(slug)] = entry
    return role_map, multi_role


def _artifact_role_slug(record: ArtifactModel, run_id: str, role_map: dict[str, dict]) -> str | None:
    if getattr(record, "role_slug", None):
        return record.role_slug
    prefix = f"{run_id}-"
    if isinstance(record.id, str) and record.id.startswith(prefix):
        remainder = record.id[len(prefix):]
        candidate = remainder.split("-", 1)[0]
        if candidate in role_map:
            return candidate
    name = record.name or ""
    for candidate in role_map:
        if name.startswith(f"{candidate}-"):
            return candidate
    return None


def _strip_role_prefix(filename: str, slug: str) -> str:
    prefix = f"{slug}-"
    if filename.startswith(prefix):
        trimmed = filename[len(prefix):]
        return trimmed or filename
    return filename


def _build_role_metadata(run_id: str, slug: str, info: dict, artifact_count: int, timestamp: str) -> dict:
    return {
        "run_id": run_id,
        "role_slug": slug,
        "label": info.get("label"),
        "auth_type": info.get("auth_type"),
        "tags": info.get("tags") or [],
        "status": info.get("status"),
        "final_url": info.get("final_url"),
        "artifact_count": artifact_count,
        "generated_at": timestamp,
    }


def _build_manifest(
    run_id: str,
    timestamp: str,
    role_map: dict[str, dict],
    artifact_counts: dict[str, int],
    shared_count: int,
) -> dict:
    roles = []
    for slug, info in role_map.items():
        roles.append(
            {
                "slug": slug,
                "label": info.get("label"),
                "status": info.get("status"),
                "final_url": info.get("final_url"),
                "artifact_count": artifact_counts.get(slug, 0),
            }
        )
    return {
        "run_id": run_id,
        "generated_at": timestamp,
        "roles": roles,
        "shared_artifacts": shared_count,
    }


@router.post(
    "/{run_id}/artifacts/{artifact_id}/verify",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Replay a .side script in a clean browser to check it logs in",
)
async def verify_side_artifact(
    run_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> dict:
    """Queue a replay of the script (one more login attempt against the target).
    The result appears on the run (``was_setup.scripts[].verification``)."""
    from app.services.queue import get_queue
    from app.services.side_replay import set_verification
    from app.services.was_setup import side_verifications

    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")
    artifact = db.get(ArtifactModel, artifact_id)
    if not artifact or artifact.run_id != run_id or artifact.type != ArtifactType.side_file.value:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Script not found")
    current = side_verifications(run).get(artifact_id) or {}
    if current.get("status") in ("queued", "running"):
        return current  # one replay at a time per script: each is a real login
    set_verification(run, artifact_id, {"status": "queued"})
    db.commit()
    get_queue().enqueue("app.services.side_replay.verify_side_artifact", run_id, artifact_id, job_timeout=300)
    return side_verifications(run)[artifact_id]
