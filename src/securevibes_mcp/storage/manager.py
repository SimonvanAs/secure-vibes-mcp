"""Storage manager for security scan artifacts."""

from pathlib import Path

# Valid artifact names that can be stored
VALID_ARTIFACTS = frozenset(
    {
        "SECURITY.md",
        "THREAT_MODEL.json",
        "VULNERABILITIES.json",
        "DAST_VALIDATION.json",
        "scan_results.json",
    }
)


class ScanStateManager:
    """Manages storage of security scan artifacts.

    Stores artifacts in a `.securevibes/` directory within the project.

    Attributes:
        project_path: The root path of the project being scanned.
        storage_dir: Path to the `.securevibes/` storage directory.
    """

    def __init__(self, project_path: Path) -> None:
        """Initialize the storage manager.

        Args:
            project_path: The root path of the project being scanned.
        """
        self.project_path = project_path
        self.storage_dir = project_path / ".securevibes"

    def init(self) -> None:
        """Initialize the storage directory.

        Creates the `.securevibes/` directory if it doesn't exist.
        Idempotent - safe to call multiple times.
        """
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _validate_artifact_name(self, name: str) -> None:
        """Validate that the artifact name is allowed.

        Args:
            name: The artifact name to validate.

        Raises:
            ValueError: If the artifact name is invalid.
        """
        if name not in VALID_ARTIFACTS:
            raise ValueError(
                f"Invalid artifact name: {name}. "
                f"Valid names are: {', '.join(sorted(VALID_ARTIFACTS))}"
            )

    def write_artifact(self, name: str, content: str) -> None:
        """Write an artifact to storage.

        Creates the storage directory if it doesn't exist.

        Args:
            name: The artifact name (must be a valid artifact name).
            content: The content to write.

        Raises:
            ValueError: If the artifact name is invalid.
        """
        self._validate_artifact_name(name)
        self.init()  # Ensure directory exists
        artifact_path = self.storage_dir / name
        artifact_path.write_text(content)

    def read_artifact(self, name: str) -> str | None:
        """Read an artifact from storage.

        Args:
            name: The artifact name to read.

        Returns:
            The artifact content, or None if not found.
        """
        if not self.storage_dir.exists():
            return None

        artifact_path = self.storage_dir / name
        if not artifact_path.exists():
            return None

        return artifact_path.read_text()

    def artifact_exists(self, name: str) -> bool:
        """Check if an artifact exists.

        Args:
            name: The artifact name to check.

        Returns:
            True if the artifact exists, False otherwise.
        """
        if not self.storage_dir.exists():
            return False

        artifact_path = self.storage_dir / name
        return artifact_path.exists()
