"""Lightweight diagnostics runner (ping/traceroute/nslookup)."""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional, List

# Hostname label: 1-63 chars, alphanumeric + hyphens, no leading/trailing hyphen.
# Full hostname: one or more dot-separated labels, total length implicitly capped by label rules.
_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

from asset_store import AssetStore
from artifact_store import ArtifactStore
from auth import SessionUser

SUPPORTED_TOOLS = {
    "ping": ["ping", "-c", "4"],
    "traceroute": ["traceroute", "-m", "20"],
    "nslookup": ["nslookup"],
}

DEFAULT_TIMEOUT = 20


@dataclass
class DiagnosticsResult:
    artifact_id: str
    asset_id: Optional[str]
    tool: str
    target: str
    exit_code: int
    summary: str


class DiagnosticsManager:
    """Runs approved network utilities and stores encrypted artifacts."""

    def __init__(self, asset_store: AssetStore, artifact_store: ArtifactStore) -> None:
        self.asset_store = asset_store
        self.artifact_store = artifact_store

    def run_tool(self, *, tool: str, target: str, private: bool, user: SessionUser) -> DiagnosticsResult:
        tool = tool.lower()
        if tool not in SUPPORTED_TOOLS:
            raise ValueError(f"Unsupported tool: {tool}")
        if not target.strip():
            raise ValueError("Target required")
        _validate_target(target)

        if shutil.which(SUPPORTED_TOOLS[tool][0]) is None:
            raise RuntimeError(f"Binary '{SUPPORTED_TOOLS[tool][0]}' not available inside the container")

        command = SUPPORTED_TOOLS[tool] + [target]
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=DEFAULT_TIMEOUT,
                text=True,
            )
            exit_code = completed.returncode
            output = completed.stdout or ""
        except subprocess.TimeoutExpired as exc:
            exit_code = -1
            # TimeoutExpired carries bytes even with text=True.
            partial = exc.stdout or b""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", errors="replace")
            output = partial + "\n[diagnostics] Command timed out"

        summary = output.splitlines()[0][:200] if output else f"Completed {tool}"

        owner_key = _owner_key(user)
        sharing_scope = "private" if private else "global"
        asset = self.asset_store.resolve(
            owner_id=owner_key,
            sharing_scope=sharing_scope,
            canonical_name=_canonical_name(target),
            primary_ip=_primary_ip(target),
            identifiers=[target],
            tags=["diagnostics", tool],
            source="diagnostics",
        )

        artifact = self.artifact_store.create(
            asset_id=asset.id if asset else None,
            owner_id=owner_key,
            sharing_scope=sharing_scope,
            module="diagnostics",
            artifact_type=tool,
            summary=summary,
            metadata={
                "tool": tool,
                "target": target,
                "exit_code": exit_code,
                "command": command,
            },
            blob=output or "(no output)",
        )

        return DiagnosticsResult(
            artifact_id=artifact.id,
            asset_id=asset.id if asset else None,
            tool=tool,
            target=target,
            exit_code=exit_code,
            summary=summary,
        )

    def list_recent_runs(
        self,
        *,
        owner: SessionUser,
        limit: int = 10,
    ) -> List[DiagnosticsResult]:
        owner_key = _owner_key(owner)
        rows = self.artifact_store.list_recent(
            module="diagnostics",
            owner_key=owner_key,
            include_private=True,
            limit=limit,
        )
        results: List[DiagnosticsResult] = []
        for row in rows:
            metadata = row.details or {}
            results.append(
                DiagnosticsResult(
                    artifact_id=row.id,
                    asset_id=row.asset_id,
                    tool=metadata.get("tool", metadata.get("command", "?")),
                    target=str(metadata.get("target", "?")),
                    exit_code=int(metadata.get("exit_code", 0)),
                    summary=row.summary or metadata.get("command", ""),
                )
            )
        return results


def _validate_target(target: str) -> None:
    """Reject targets that would be interpreted as flags or are not valid hostnames/IPs.

    Prevents argument injection: a value like '-f' appended to ping becomes
    'ping -c 4 -f' (flood ping). Targets must be a bare IPv4/v6 address or a
    RFC-compliant hostname. Anything else — including leading '-', spaces, or
    shell metacharacters — is rejected with ValueError (→ HTTP 400).
    """
    if target.startswith("-"):
        raise ValueError(f"Invalid target '{target}': targets may not begin with '-'")
    if "%" not in target:  # no IPv6 zone ids: they take arbitrary text
        try:
            ipaddress.ip_address(target)
            return  # valid IPv4 or IPv6 literal
        except ValueError:
            pass
    if not _HOSTNAME_RE.fullmatch(target):  # fullmatch: '$' would allow a trailing newline
        raise ValueError(
            f"Invalid target '{target}': must be a hostname (e.g. example.com) "
            "or IP address (e.g. 1.2.3.4)"
        )


def _owner_key(user: SessionUser) -> str:
    return user.user_id or user.username


def _canonical_name(target: str) -> Optional[str]:
    try:
        ipaddress.ip_address(target)
        return None
    except ValueError:
        return target.lower()


def _primary_ip(target: str) -> Optional[str]:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return None
