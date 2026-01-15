"""Writer for suppression/baseline file."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securevibes_mcp.agents.suppression_reader import Suppression, SuppressionReader
from securevibes_mcp.storage.manager import ScanStateManager

# Valid reason values for suppressions
VALID_REASONS = frozenset(
    {"false_positive", "acceptable_risk", "will_not_fix", "mitigated"}
)


class SuppressionWriter:
    """Writer for creating and managing suppressions.

    Attributes:
        root_path: Path to the project root.
        storage: ScanStateManager for artifact access.
        reader: SuppressionReader for reading existing suppressions.
    """

    def __init__(self, root_path: Path) -> None:
        """Initialize the writer.

        Args:
            root_path: Path to the project root.
        """
        self.root_path = root_path
        self.storage = ScanStateManager(root_path)
        self.reader = SuppressionReader(root_path)

    def _read_or_create(self) -> dict[str, Any]:
        """Read existing data or create empty structure.

        Returns:
            Suppressions data dict.
        """
        data = self.reader.read()
        if data is None:
            return {"version": "1.0.0", "suppressions": []}
        return data

    def _write(self, data: dict[str, Any]) -> None:
        """Write data to SUPPRESSIONS.json.

        Args:
            data: Suppressions data dict.
        """
        content = json.dumps(data, indent=2)
        self.storage.write_artifact("SUPPRESSIONS.json", content)

    def _next_id(self, data: dict[str, Any]) -> str:
        """Generate the next suppression ID.

        Args:
            data: Current suppressions data.

        Returns:
            Next ID in format SUPP-NNN.
        """
        suppressions = data.get("suppressions", [])
        if not suppressions:
            return "SUPP-001"

        # Find highest existing ID
        max_num = 0
        for s in suppressions:
            sid = s.get("id", "")
            if sid.startswith("SUPP-"):
                try:
                    num = int(sid[5:])
                    max_num = max(max_num, num)
                except ValueError:
                    pass
        return f"SUPP-{max_num + 1:03d}"

    def add(
        self,
        suppression_type: str,
        vuln_id: str | None = None,
        pattern: str | None = None,
        cwe_id: str | None = None,
        reason: str = "false_positive",
        justification: str = "",
        suppressed_by: str | None = None,
        expires_at: str | None = None,
    ) -> Suppression:
        """Add a new suppression.

        Args:
            suppression_type: Type of suppression (vuln_id, file_pattern, cwe_pattern).
            vuln_id: Vulnerability ID (for vuln_id type).
            pattern: File path pattern (for file_pattern type).
            cwe_id: CWE ID (for cwe_pattern type).
            reason: Reason for suppression.
            justification: Detailed justification.
            suppressed_by: Who created the suppression.
            expires_at: ISO timestamp when suppression expires.

        Returns:
            Created Suppression object.

        Raises:
            ValueError: If invalid type or reason provided.
        """
        # Validate type
        if suppression_type not in ("vuln_id", "file_pattern", "cwe_pattern"):
            raise ValueError(
                f"Invalid suppression type: {suppression_type}. "
                "Must be one of: vuln_id, file_pattern, cwe_pattern"
            )

        # Validate reason
        if reason not in VALID_REASONS:
            raise ValueError(
                f"Invalid reason: {reason}. "
                f"Must be one of: {', '.join(sorted(VALID_REASONS))}"
            )

        # Validate type-specific fields
        if suppression_type == "vuln_id" and not vuln_id:
            raise ValueError("vuln_id is required for vuln_id type")
        if suppression_type == "file_pattern" and not pattern:
            raise ValueError("pattern is required for file_pattern type")
        if suppression_type == "cwe_pattern" and not cwe_id:
            raise ValueError("cwe_id is required for cwe_pattern type")

        data = self._read_or_create()
        suppression_id = self._next_id(data)

        suppression = Suppression(
            id=suppression_id,
            type=suppression_type,
            vuln_id=vuln_id,
            pattern=pattern,
            cwe_id=cwe_id,
            reason=reason,
            justification=justification,
            suppressed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            suppressed_by=suppressed_by,
            expires_at=expires_at,
        )

        data["suppressions"].append(suppression.to_dict())
        self._write(data)

        return suppression

    def remove(self, suppression_id: str) -> bool:
        """Remove a suppression by ID.

        Args:
            suppression_id: The suppression ID to remove.

        Returns:
            True if removed, False if not found.
        """
        data = self._read_or_create()
        suppressions = data.get("suppressions", [])

        original_count = len(suppressions)
        data["suppressions"] = [s for s in suppressions if s.get("id") != suppression_id]

        if len(data["suppressions"]) < original_count:
            self._write(data)
            return True
        return False
