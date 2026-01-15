"""Storage manager for security scan artifacts."""

from pathlib import Path

from securevibes_mcp.storage.errors import StorageError

# Valid artifact names that can be stored
VALID_ARTIFACTS = frozenset(
    {
        "SECURITY.md",
        "THREAT_MODEL.json",
        "VULNERABILITIES.json",
        "SUPPRESSIONS.json",
        "DAST_VALIDATION.json",
        "scan_results.json",
        "scan_report.md",
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

        Raises:
            StorageError: If directory creation fails due to permissions.
        """
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            raise StorageError(
                f"Cannot create storage directory: {e}",
                code="PERMISSION_DENIED",
                path=str(self.storage_dir),
            ) from e

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
            StorageError: If write fails due to permissions.
        """
        self._validate_artifact_name(name)
        self.init()  # Ensure directory exists
        artifact_path = self.storage_dir / name
        try:
            artifact_path.write_text(content)
        except PermissionError as e:
            raise StorageError(
                f"Cannot write artifact: {e}",
                code="PERMISSION_DENIED",
                path=str(artifact_path),
            ) from e

    def read_artifact(self, name: str) -> str | None:
        """Read an artifact from storage.

        Args:
            name: The artifact name to read.

        Returns:
            The artifact content, or None if not found or not readable.
        """
        if not self.storage_dir.exists():
            return None

        artifact_path = self.storage_dir / name
        if not artifact_path.exists():
            return None

        try:
            return artifact_path.read_text()
        except PermissionError:
            return None

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

    def get_status(self) -> dict[str, dict[str, bool | int | float | None]]:
        """Get status of all artifacts.

        Returns:
            Dictionary mapping artifact names to their status.
            Each status contains:
            - exists: Whether the artifact exists
            - size: File size in bytes (None if not exists)
            - modified_at: Modification timestamp as float (None if not exists)
        """
        status: dict[str, dict[str, bool | int | float | None]] = {}

        for artifact_name in VALID_ARTIFACTS:
            artifact_path = self.storage_dir / artifact_name

            if self.storage_dir.exists() and artifact_path.exists():
                stat = artifact_path.stat()
                status[artifact_name] = {
                    "exists": True,
                    "size": stat.st_size,
                    "modified_at": stat.st_mtime,
                }
            else:
                status[artifact_name] = {
                    "exists": False,
                    "size": None,
                    "modified_at": None,
                }

        return status
