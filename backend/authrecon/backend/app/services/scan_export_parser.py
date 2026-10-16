"""Tenable WAS scan export intake: validate an upload safely (bounded sizes,
no extraction to disk, zip-bomb checks), inventory it, and attach the
analysis from services/scan_analysis.py.

Accepted: the scan's debug .zip, or a single JSON, .nessus, CSV, XML or HAR
export (wrapped into a zip in memory so everything takes one path). The
summary is what MCP tools hand to an AI client, so it carries no credentials
or raw target content (see scan_analysis).
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MAX_ENTRIES = 5_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200  # per entry; guards against zip bombs
PARSER_VERSION = "1"
SINGLE_FILE_TYPES = (".json", ".nessus", ".csv", ".xml", ".har")


class ScanExportError(ValueError):
    """The upload is not an acceptable scan export (shown to the user)."""


@dataclass
class ParsedExport:
    summary: dict
    zip_bytes: bytes  # what to store: the upload, or a single file wrapped in a zip


def as_zip(data: bytes, filename: str | None) -> bytes:
    """The upload as a zip: unchanged if it is one, else a single supported file wrapped."""
    if zipfile.is_zipfile(io.BytesIO(data)):
        return data
    name = (filename or "").replace("\\", "/").rsplit("/", 1)[-1] or "export"
    if not name.lower().endswith(SINGLE_FILE_TYPES):
        raise ScanExportError("Upload a WAS export: the scan's .zip, or a .json, .nessus, .csv, .xml or .har file")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, data)
    return buffer.getvalue()


def _kind(name: str) -> str:
    lowered = name.lower()
    for ext, kind in ((".json", "json"), (".csv", "csv"), (".xml", "xml"), (".html", "html"), (".htm", "html"),
                      (".har", "har"),
                      (".nessus", "nessus"), (".pdf", "pdf"), (".txt", "text"), (".log", "text")):
        if lowered.endswith(ext):
            return kind
    return "other"


def parse_export(data: bytes, filename: str | None = None) -> ParsedExport:
    """Validate the upload, inventory it and analyze it. Never extracts to disk."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise ScanExportError(f"Export is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    data = as_zip(data, filename)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if len(infos) > MAX_ENTRIES:
                raise ScanExportError(f"Export has more than {MAX_ENTRIES} files")
            total = sum(i.file_size for i in infos)
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ScanExportError("Export expands to more than 2 GB")
            for info in infos:
                if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                    raise ScanExportError("Export looks like a zip bomb (compression ratio too high)")
                if info.flag_bits & 0x1:
                    raise ScanExportError("Encrypted zips are not supported")
    except zipfile.BadZipFile as exc:
        raise ScanExportError("Upload is not a readable zip") from exc

    from app.services.scan_analysis import analyze

    by_kind: dict[str, int] = {}
    for info in infos:
        kind = _kind(info.filename)
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return ParsedExport(summary={
        "parser_version": PARSER_VERSION,
        "file_count": len(infos),
        "uncompressed_bytes": total,
        "files_by_kind": by_kind,
        # Names only (no contents).
        "files": [{"name": i.filename, "size": i.file_size, "kind": _kind(i.filename)} for i in infos[:200]],
        "analysis": analyze(data),
    }, zip_bytes=data)
