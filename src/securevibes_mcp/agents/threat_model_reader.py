"""THREAT_MODEL.json reader for the Code Review Agent."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securevibes_mcp.storage import ScanStateManager


@dataclass
class ParsedThreatEntry:
    """A parsed threat entry from THREAT_MODEL.json.

    Attributes:
        id: Unique threat identifier (e.g., THREAT-001).
        category: STRIDE category.
        component: Affected component name.
        description: Threat description.
        attack_vector: How the threat could be exploited.
        impact: Potential business/security impact.
        severity: Severity level (critical, high, medium, low).
        cvss_min: Minimum CVSS score.
        cvss_max: Maximum CVSS score.
    """

    id: str
    category: str
    component: str
    description: str
    attack_vector: str
    impact: str
    severity: str
    cvss_min: float
    cvss_max: float


class ThreatModelReader:
    """Reader for loading and parsing THREAT_MODEL.json artifacts.

    Uses ScanStateManager to read the threat model from the project's
    .securevibes directory and parses it into structured objects.
    """

    ARTIFACT_NAME = "THREAT_MODEL.json"

    def __init__(self, root_path: Path) -> None:
        """Initialize the reader.

        Args:
            root_path: Root path of the project.
        """
        self.root_path = root_path
        self.storage = ScanStateManager(root_path)

    def read(self) -> dict[str, Any] | None:
        """Read the THREAT_MODEL.json artifact.

        Returns:
            Parsed JSON content as dictionary, or None if not found or invalid.
        """
        content = self.storage.read_artifact(self.ARTIFACT_NAME)
        if content is None:
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    def get_threats(self) -> list[ParsedThreatEntry]:
        """Get all threats as parsed entries.

        Returns:
            List of ParsedThreatEntry objects, empty if artifact missing.
        """
        data = self.read()
        if data is None:
            return []

        threats = data.get("threats", [])
        return [self._parse_threat_entry(t) for t in threats]

    def _parse_threat_entry(self, entry: dict[str, Any]) -> ParsedThreatEntry:
        """Parse a raw threat entry dictionary into ParsedThreatEntry.

        Args:
            entry: Raw threat entry dictionary from JSON.

        Returns:
            ParsedThreatEntry with all fields populated.
        """
        cvss_range = entry.get("cvss_range", {})
        return ParsedThreatEntry(
            id=entry["id"],
            category=entry["category"],
            component=entry["component"],
            description=entry["description"],
            attack_vector=entry["attack_vector"],
            impact=entry["impact"],
            severity=entry["severity"],
            cvss_min=cvss_range.get("min", 0.0),
            cvss_max=cvss_range.get("max", 0.0),
        )
