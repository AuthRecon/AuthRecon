"""Tool registry loader for the portal."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import yaml

DEFAULT_TOOLS = [
    {
        "id": "auth_recon",
        "name": "Auth Recon",
        "description": "Authentication reconnaissance and reporting suite.",
        "url": "http://127.0.0.1:8080",
        "status_url": "http://127.0.0.1:8080/status",
        "tags": ["auth", "reporting"],
        "enabled": True,
        "service_id": "auth_recon",
        "sso_enabled": True,
        "sso_entry_url": "http://127.0.0.1:8080",
    },
]


class ToolRegistry:
    """Loads and exposes registered tools."""

    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self._tools: List[Dict[str, str]] = []

    def load_tools(self) -> None:
        """Load tools from YAML or fallback to defaults."""
        if not self.config_path.exists():
            self._tools = DEFAULT_TOOLS
            return
        with open(self.config_path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or []
            self._tools = data

    def list_tools(self) -> List[Dict[str, str]]:
        """Return all enabled tools."""
        return [tool for tool in self._tools if tool.get("enabled", True)]

    def get_tool(self, tool_id: str) -> Dict[str, str]:
        """Return a specific tool definition."""
        match_id = str(tool_id).strip().lower()
        for tool in self._tools:
            if str(tool.get("id", "")).strip().lower() == match_id:
                return tool
        raise KeyError(f"Unknown tool id '{tool_id}'")
