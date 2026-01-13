"""THREAT_MODEL.json reader for the Code Review Agent."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securevibes_mcp.storage import ScanStateManager


@dataclass
class ThreatValidationError:
    """Validation error for a threat entry.

    Attributes:
        threat_index: Index of the threat entry in the threats list.
        field: Name of the field that failed validation.
        message: Description of the validation error.
    """

    threat_index: int
    field: str
    message: str


# Required fields for threat entry validation
REQUIRED_THREAT_FIELDS = frozenset({"id", "category", "component", "severity"})


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

    def _validate_threat_entry(
        self, entry: dict[str, Any], index: int
    ) -> list[ThreatValidationError]:
        """Validate a single threat entry.

        Args:
            entry: Raw threat entry dictionary from JSON.
            index: Index of the entry in the threats list.

        Returns:
            List of validation errors (empty if valid).
        """
        errors: list[ThreatValidationError] = []

        for field in REQUIRED_THREAT_FIELDS:
            if field not in entry or not entry[field]:
                errors.append(
                    ThreatValidationError(
                        threat_index=index,
                        field=field,
                        message=f"Missing required field: {field}",
                    )
                )

        return errors

    def get_validation_errors(self) -> list[ThreatValidationError]:
        """Get all validation errors for threat entries.

        Returns:
            List of validation errors across all threat entries.
        """
        data = self.read()
        if data is None:
            return []

        threats = data.get("threats", [])
        errors: list[ThreatValidationError] = []

        for index, threat in enumerate(threats):
            errors.extend(self._validate_threat_entry(threat, index))

        return errors

    def get_validated_threats(self) -> list[ParsedThreatEntry]:
        """Get only valid threats as parsed entries.

        Invalid entries are silently skipped. Use get_validation_errors()
        to inspect what entries failed validation.

        Returns:
            List of ParsedThreatEntry objects for valid entries only.
        """
        data = self.read()
        if data is None:
            return []

        threats = data.get("threats", [])
        valid_threats: list[ParsedThreatEntry] = []

        for index, threat in enumerate(threats):
            errors = self._validate_threat_entry(threat, index)
            if not errors:
                valid_threats.append(self._parse_threat_entry(threat))

        return valid_threats
