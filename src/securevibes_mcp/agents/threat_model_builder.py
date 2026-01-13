"""Threat model builder for generating THREAT_MODEL.json."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from securevibes_mcp.agents.severity import SeverityClassifier
from securevibes_mcp.agents.stride_analyzer import ThreatFinding


@dataclass
class ThreatEntry:
    """A single threat entry in the threat model.

    Attributes:
        id: Unique threat identifier (e.g., THREAT-001).
        category: STRIDE category.
        component: Affected component name.
        description: Threat description.
        attack_vector: How the threat could be exploited.
        impact: Potential business/security impact.
        severity: Severity level (critical, high, medium, low).
        cvss_range: CVSS score range as (min, max).
    """

    id: str
    category: str
    component: str
    description: str
    attack_vector: str
    impact: str
    severity: str
    cvss_range: tuple[float, float]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all threat entry fields.
        """
        return {
            "id": self.id,
            "category": self.category,
            "component": self.component,
            "description": self.description,
            "attack_vector": self.attack_vector,
            "impact": self.impact,
            "severity": self.severity,
            "cvss_range": {
                "min": self.cvss_range[0],
                "max": self.cvss_range[1],
            },
        }


@dataclass
class ThreatModel:
    """Complete threat model containing all identified threats.

    Attributes:
        version: Schema version.
        generated_at: ISO timestamp of generation.
        project_path: Path to the analyzed project.
        threats: List of ThreatEntry objects.
        summary: Summary statistics.
    """

    version: str
    generated_at: str
    project_path: str
    threats: list[ThreatEntry]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary suitable for JSON serialization.
        """
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "project_path": self.project_path,
            "threats": [t.to_dict() for t in self.threats],
            "summary": self.summary,
        }


class ThreatModelBuilder:
    """Builder for constructing threat models from findings.

    Generates unique threat IDs, applies severity classification,
    and builds complete threat model structures.
    """

    def __init__(self, project_path: str) -> None:
        """Initialize the builder.

        Args:
            project_path: Path to the project being analyzed.
        """
        self.project_path = project_path
        self.severity_classifier = SeverityClassifier()
        self._threat_counter = 0

    def generate_threat_id(self) -> str:
        """Generate a unique threat ID.

        Returns:
            Unique threat ID in format THREAT-NNN.
        """
        self._threat_counter += 1
        return f"THREAT-{self._threat_counter:03d}"

    def build_threat_entry(self, finding: ThreatFinding) -> ThreatEntry:
        """Build a ThreatEntry from a ThreatFinding.

        Args:
            finding: The ThreatFinding to convert.

        Returns:
            ThreatEntry with unique ID and CVSS range.
        """
        normalized_severity = self.severity_classifier.normalize(finding.severity)
        cvss_range = self.severity_classifier.get_cvss_range(normalized_severity)

        return ThreatEntry(
            id=self.generate_threat_id(),
            category=finding.category,
            component=finding.component,
            description=finding.description,
            attack_vector=finding.attack_vector,
            impact=finding.impact,
            severity=normalized_severity,
            cvss_range=cvss_range,
        )

    def _build_summary(self, entries: list[ThreatEntry]) -> dict[str, Any]:
        """Build summary statistics for threat entries.

        Args:
            entries: List of ThreatEntry objects.

        Returns:
            Summary dictionary with counts.
        """
        summary: dict[str, Any] = {"total": len(entries)}

        # Count by severity
        severity_counts: dict[str, int] = {}
        for entry in entries:
            severity_counts[entry.severity] = severity_counts.get(entry.severity, 0) + 1
        summary.update(severity_counts)

        # Count by category
        category_counts: dict[str, int] = {}
        for entry in entries:
            category_counts[entry.category] = category_counts.get(entry.category, 0) + 1
        summary["by_category"] = category_counts

        return summary

    def build(self, findings: list[ThreatFinding]) -> ThreatModel:
        """Build a complete ThreatModel from findings.

        Args:
            findings: List of ThreatFinding objects.

        Returns:
            Complete ThreatModel ready for serialization.
        """
        entries = [self.build_threat_entry(f) for f in findings]
        summary = self._build_summary(entries)

        return ThreatModel(
            version="1.0",
            generated_at=datetime.now(UTC).isoformat(),
            project_path=self.project_path,
            threats=entries,
            summary=summary,
        )
