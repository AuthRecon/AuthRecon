"""
Telemetry Collector
Captures detailed authentication attempt data for AuthRecon validation.
"""
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel


class TelemetryEntry(BaseModel):
    """Single telemetry entry for an authentication attempt."""
    id: str
    run_id: Optional[str] = None
    scenario: str
    timestamp: str
    request: Dict
    response: Dict
    detection_hints: Dict
    success: bool


class TelemetryCollector:
    """Collects and stores telemetry data for testing."""

    def __init__(self):
        self.entries: List[TelemetryEntry] = []

    def record(
        self,
        scenario: str,
        request_data: Dict,
        response_data: Dict,
        detection_hints: Dict,
        success: bool,
        run_id: Optional[str] = None,
    ) -> str:
        """Record a telemetry entry."""
        entry_id = str(uuid.uuid4())
        entry = TelemetryEntry(
            id=entry_id,
            run_id=run_id,
            scenario=scenario,
            timestamp=datetime.utcnow().isoformat(),
            request=request_data,
            response=response_data,
            detection_hints=detection_hints,
            success=success,
        )
        self.entries.append(entry)
        return entry_id

    def get_by_id(self, entry_id: str) -> Optional[TelemetryEntry]:
        """Get telemetry entry by ID."""
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        return None

    def get_by_run_id(self, run_id: str) -> List[TelemetryEntry]:
        """Get all telemetry entries for a specific run."""
        return [e for e in self.entries if e.run_id == run_id]

    def list_recent(
        self,
        scenario: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[TelemetryEntry]:
        """List recent telemetry entries."""
        entries = self.entries
        if scenario:
            entries = [e for e in entries if e.scenario == scenario]

        # Sort by timestamp descending
        entries = sorted(
            entries,
            key=lambda e: e.timestamp,
            reverse=True,
        )

        return entries[offset : offset + limit]

    def total_attempts(self) -> int:
        """Get total number of attempts."""
        return len(self.entries)

    def successful_attempts(self) -> int:
        """Get number of successful attempts."""
        return sum(1 for e in self.entries if e.success)

    def scenario_stats(self, scenario: str) -> Dict:
        """Get statistics for a specific scenario."""
        entries = [e for e in self.entries if e.scenario == scenario]
        total = len(entries)
        successful = sum(1 for e in entries if e.success)

        return {
            "total": total,
            "successful": successful,
            "failed": total - successful,
            "success_rate": successful / total if total > 0 else 0,
        }

    def reset(self):
        """Clear all telemetry data."""
        self.entries.clear()
