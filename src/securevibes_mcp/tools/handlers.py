"""Tool handler implementations for SecureVibes MCP."""

from pathlib import Path
from typing import Any

from securevibes_mcp.storage import ScanStateManager
from securevibes_mcp.storage.manager import VALID_ARTIFACTS


def _validate_path(path: str) -> dict[str, Any] | None:
    """Validate that a path exists and is a directory.

    Args:
        path: Path to validate.

    Returns:
        Error dict if validation fails, None if valid.
    """
    project_path = Path(path)

    if not project_path.exists():
        return {
            "error": True,
            "code": "PATH_NOT_FOUND",
            "message": f"Path does not exist: {path}",
            "path": path,
        }

    if not project_path.is_dir():
        return {
            "error": True,
            "code": "PATH_NOT_DIRECTORY",
            "message": f"Path is not a directory: {path}",
            "path": path,
        }

    return None


async def get_scan_status(path: str, **_kwargs: Any) -> dict[str, Any]:
    """Get the status of all security scan artifacts.

    Args:
        path: Absolute path to the codebase.

    Returns:
        Dictionary with artifact statuses.
    """
    # Validate path
    error = _validate_path(path)
    if error:
        return error

    project_path = Path(path)
    manager = ScanStateManager(project_path)
    status = manager.get_status()

    return {
        "error": False,
        "path": path,
        "artifacts": status,
    }


async def get_artifact(
    path: str, artifact_name: str, **_kwargs: Any
) -> dict[str, Any]:
    """Get the content of a specific artifact.

    Args:
        path: Absolute path to the codebase.
        artifact_name: Name of the artifact to retrieve.

    Returns:
        Dictionary with artifact content or error.
    """
    # Validate path
    error = _validate_path(path)
    if error:
        return error

    # Validate artifact name
    if artifact_name not in VALID_ARTIFACTS:
        return {
            "error": True,
            "code": "INVALID_ARTIFACT_NAME",
            "message": f"Invalid artifact name: {artifact_name}",
            "artifact_name": artifact_name,
        }

    project_path = Path(path)
    manager = ScanStateManager(project_path)

    content = manager.read_artifact(artifact_name)
    if content is None:
        return {
            "error": True,
            "code": "ARTIFACT_NOT_FOUND",
            "message": f"Artifact not found: {artifact_name}",
            "artifact_name": artifact_name,
            "path": path,
        }

    return {
        "error": False,
        "artifact_name": artifact_name,
        "content": content,
        "size": len(content),
        "path": path,
    }
