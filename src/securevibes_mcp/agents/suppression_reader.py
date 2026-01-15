"""Reader for suppression/baseline file."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securevibes_mcp.storage.manager import ScanStateManager


@dataclass
class Suppression:
    """A suppression entry for excluding vulnerabilities from results.

    Attributes:
        id: Unique suppression identifier (SUPP-001, SUPP-002, etc.).
        type: Type of suppression (vuln_id, file_pattern, cwe_pattern).
        vuln_id: Specific vulnerability ID to suppress (for vuln_id type).
        pattern: File path pattern to suppress (for file_pattern type).
        cwe_id: CWE ID to suppress (for cwe_pattern type).
        reason: Reason for suppression.
        justification: Detailed justification text.
        suppressed_at: ISO timestamp when suppression was created.
        suppressed_by: Who created the suppression.
        expires_at: ISO timestamp when suppression expires (optional).
    """

    id: str
    type: str
    vuln_id: str | None
    pattern: str | None
    cwe_id: str | None
    reason: str
    justification: str
    suppressed_at: str
    suppressed_by: str | None = None
    expires_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Suppression":
        """Create a Suppression from a dictionary.

        Args:
            data: Dictionary with suppression data.

        Returns:
            Suppression instance.
        """
        return cls(
            id=data.get("id", ""),
            type=data.get("type", "vuln_id"),
            vuln_id=data.get("vuln_id"),
            pattern=data.get("pattern"),
            cwe_id=data.get("cwe_id"),
            reason=data.get("reason", ""),
            justification=data.get("justification", ""),
            suppressed_at=data.get("suppressed_at", ""),
            suppressed_by=data.get("suppressed_by"),
            expires_at=data.get("expires_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with suppression data.
        """
        result: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "reason": self.reason,
            "justification": self.justification,
            "suppressed_at": self.suppressed_at,
        }
        if self.vuln_id:
            result["vuln_id"] = self.vuln_id
        if self.pattern:
            result["pattern"] = self.pattern
        if self.cwe_id:
            result["cwe_id"] = self.cwe_id
        if self.suppressed_by:
            result["suppressed_by"] = self.suppressed_by
        if self.expires_at:
            result["expires_at"] = self.expires_at
        return result

    def is_expired(self) -> bool:
        """Check if the suppression has expired.

        Returns:
            True if expired, False otherwise.
        """
        if not self.expires_at:
            return False
        try:
            expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > expires
        except ValueError:
            return False


class SuppressionReader:
    """Reader for loading suppressions from SUPPRESSIONS.json.

    Attributes:
        root_path: Path to the project root.
        storage: ScanStateManager for artifact access.
    """

    def __init__(self, root_path: Path) -> None:
        """Initialize the reader.

        Args:
            root_path: Path to the project root.
        """
        self.root_path = root_path
        self.storage = ScanStateManager(root_path)

    def read(self) -> dict[str, Any] | None:
        """Read the raw SUPPRESSIONS.json content.

        Returns:
            Parsed JSON dict or None if not found.
        """
        content = self.storage.read_artifact("SUPPRESSIONS.json")
        if content is None:
            return None
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    def get_suppressions(self, include_expired: bool = False) -> list[Suppression]:
        """Get all suppressions.

        Args:
            include_expired: Include expired suppressions.

        Returns:
            List of Suppression objects.
        """
        data = self.read()
        if not data:
            return []

        suppressions = []
        for item in data.get("suppressions", []):
            suppression = Suppression.from_dict(item)
            if include_expired or not suppression.is_expired():
                suppressions.append(suppression)
        return suppressions

    def get_suppressed_vuln_ids(self) -> set[str]:
        """Get set of directly suppressed vulnerability IDs.

        Returns:
            Set of vulnerability IDs that are suppressed by vuln_id type.
        """
        suppressed = set()
        for s in self.get_suppressions():
            if s.type == "vuln_id" and s.vuln_id:
                suppressed.add(s.vuln_id)
        return suppressed

    def is_suppressed(self, vuln: dict[str, Any]) -> bool:
        """Check if a vulnerability is suppressed.

        Checks against all suppression types:
        - vuln_id: Direct ID match
        - file_pattern: File path contains pattern
        - cwe_pattern: CWE ID match

        Args:
            vuln: Vulnerability dict with id, file_path, cwe_id fields.

        Returns:
            True if suppressed, False otherwise.
        """
        return self.get_matching_suppression(vuln) is not None

    def get_matching_suppression(
        self, vuln: dict[str, Any]
    ) -> Suppression | None:
        """Get the suppression that matches a vulnerability.

        Args:
            vuln: Vulnerability dict with id, file_path, cwe_id fields.

        Returns:
            Matching Suppression or None.
        """
        vuln_id = vuln.get("id", "")
        file_path = vuln.get("file_path", "") or ""
        cwe_id = vuln.get("cwe_id", "")

        for suppression in self.get_suppressions():
            # Check vuln_id match
            if suppression.type == "vuln_id" and suppression.vuln_id == vuln_id:
                return suppression

            # Check file_pattern match
            if suppression.type == "file_pattern" and suppression.pattern:
                if suppression.pattern in file_path:
                    return suppression

            # Check cwe_pattern match
            if suppression.type == "cwe_pattern" and suppression.cwe_id == cwe_id:
                return suppression

        return None
