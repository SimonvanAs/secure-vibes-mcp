"""Dependency validation for security scan tools."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securevibes_mcp.storage import ScanStateManager

# Tool dependency mapping - defines which artifacts each tool requires
TOOL_DEPENDENCIES: dict[str, list[str]] = {
    "run_assessment": [],  # Entry point - no dependencies
    "run_threat_modeling": ["SECURITY.md"],
    "run_code_review": ["THREAT_MODEL.json"],
    "run_dast": ["VULNERABILITIES.json"],
    "generate_report": ["SECURITY.md"],
}


@dataclass
class ValidationResult:
    """Result of dependency validation.

    Attributes:
        tool: Name of the tool being validated.
        required: List of required artifact names.
        missing: List of missing artifact names.
        satisfied: True if all dependencies are satisfied.
    """

    tool: str
    required: list[str]
    missing: list[str]
    satisfied: bool

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all validation result fields.
        """
        return {
            "tool": self.tool,
            "required": self.required,
            "missing": self.missing,
            "satisfied": self.satisfied,
        }


class DependencyValidator:
    """Validates that tool dependencies are satisfied.

    Checks if required artifacts exist before a tool can be executed.

    Attributes:
        root_path: Path to the project root.
        manager: ScanStateManager for checking artifact existence.
    """

    def __init__(self, root_path: Path) -> None:
        """Initialize the dependency validator.

        Args:
            root_path: Path to the project root.
        """
        self.root_path = root_path
        self.manager = ScanStateManager(root_path)

    def get_dependencies(self, tool_name: str) -> list[str]:
        """Get the list of required artifacts for a tool.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            List of artifact names required by the tool.
        """
        return TOOL_DEPENDENCIES.get(tool_name, [])

    def validate(self, tool_name: str) -> ValidationResult:
        """Validate that all dependencies for a tool are satisfied.

        Args:
            tool_name: Name of the tool to validate.

        Returns:
            ValidationResult with details about satisfied/missing dependencies.
        """
        required = self.get_dependencies(tool_name)
        missing = [
            artifact
            for artifact in required
            if not self.manager.artifact_exists(artifact)
        ]

        return ValidationResult(
            tool=tool_name,
            required=required,
            missing=missing,
            satisfied=len(missing) == 0,
        )
