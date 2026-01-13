"""DAST output structures and writer."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json

from securevibes_mcp.storage import ScanStateManager


@dataclass
class DASTValidation:
    """Represents a single DAST validation result."""

    vulnerability_id: str
    exploitable: bool
    evidence: str
    http_status: int | None = None
    response_time_ms: float | None = None
    test_payload: str | None = None
    notes: str = ""
    severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all validation fields.
        """
        return {
            "vulnerability_id": self.vulnerability_id,
            "exploitable": self.exploitable,
            "evidence": self.evidence,
            "http_status": self.http_status,
            "response_time_ms": self.response_time_ms,
            "test_payload": self.test_payload,
            "notes": self.notes,
        }


@dataclass
class DASTValidationOutput:
    """Container for all DAST validation results."""

    target_url: str
    validations: list[DASTValidation] = field(default_factory=list)
    version: str = "1.0.0"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def add_validation(self, validation: DASTValidation) -> None:
        """Add a validation result.

        Args:
            validation: The validation result to add.
        """
        self.validations.append(validation)

    def get_summary(self) -> dict[str, Any]:
        """Get summary statistics of validations.

        Returns:
            Dictionary with summary statistics.
        """
        exploitable_count = sum(1 for v in self.validations if v.exploitable)
        not_exploitable_count = len(self.validations) - exploitable_count

        # Count by severity
        by_severity: dict[str, int] = {}
        for v in self.validations:
            if v.severity:
                by_severity[v.severity] = by_severity.get(v.severity, 0) + 1

        return {
            "total_tested": len(self.validations),
            "exploitable": exploitable_count,
            "not_exploitable": not_exploitable_count,
            "by_severity": by_severity,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all output fields.
        """
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "target_url": self.target_url,
            "validations": [v.to_dict() for v in self.validations],
            "summary": self.get_summary(),
        }

    def to_json(self) -> str:
        """Convert to JSON string.

        Returns:
            JSON string representation.
        """
        return json.dumps(self.to_dict(), indent=2)


class DASTValidationWriter:
    """Writer for DAST_VALIDATION.json artifact."""

    ARTIFACT_NAME = "DAST_VALIDATION.json"

    def __init__(self, root_path: Path) -> None:
        """Initialize the writer.

        Args:
            root_path: Root path of the project.
        """
        self.root_path = root_path
        self.storage = ScanStateManager(root_path)

    def write(self, output: DASTValidationOutput) -> None:
        """Write the DAST validation output artifact.

        Args:
            output: The DAST validation output to write.
        """
        content = output.to_json()
        self.storage.write_artifact(self.ARTIFACT_NAME, content)
