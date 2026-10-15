"""Tenable WAS scan export parsing (SCAFFOLD).

Today this only inventories the zip safely (no extraction, bounded sizes) so
the upload pipeline, storage, API and MCP tools can be built and tested end to
end. TODO(scan-analyzer): parse the real WAS export format into findings that
help diagnose scan problems (timeouts, needed exclusions, scan breakdowns),
and keep the summary free of credentials and raw target content: it is what
MCP tools hand to an AI client.
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MAX_ENTRIES = 5_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200  # per entry; guards against zip bombs
PARSER_VERSION = "scaffold-0"


class ScanExportError(ValueError):
    """The upload is not an acceptable scan export (shown to the user)."""


@dataclass
class ParsedExport:
    summary: dict


def _kind(name: str) -> str:
    lowered = name.lower()
    for ext, kind in ((".json", "json"), (".csv", "csv"), (".xml", "xml"), (".html", "html"), (".htm", "html"),
                      (".nessus", "nessus"), (".pdf", "pdf"), (".txt", "text"), (".log", "text")):
        if lowered.endswith(ext):
            return kind
    return "other"


def parse_export(data: bytes) -> ParsedExport:
    """Validate the zip and return a safe inventory. Never extracts to disk."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise ScanExportError(f"Export is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise ScanExportError("Upload must be a .zip scan export")
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

    by_kind: dict[str, int] = {}
    for info in infos:
        kind = _kind(info.filename)
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return ParsedExport(summary={
        "parser_version": PARSER_VERSION,
        "file_count": len(infos),
        "uncompressed_bytes": total,
        "files_by_kind": by_kind,
        # Names only (no contents). The real parser will replace this with findings.
        "files": [{"name": i.filename, "size": i.file_size, "kind": _kind(i.filename)} for i in infos[:200]],
        "findings": None,  # TODO(scan-analyzer)
    })
