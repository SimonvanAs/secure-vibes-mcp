"""Tool handler implementations for SecureVibes MCP."""

from pathlib import Path
from typing import Any

from securevibes_mcp.agents.code_review_handler import CodeReviewHandler
from securevibes_mcp.agents.dast_handler import DASTHandler
from securevibes_mcp.agents.generator import SecurityDocGenerator
from securevibes_mcp.agents.report_handler import ReportHandler
from securevibes_mcp.agents.scanner import CodebaseScanner
from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
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


async def get_artifact(path: str, artifact_name: str, **_kwargs: Any) -> dict[str, Any]:
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


async def run_assessment(
    path: str,
    force: bool = False,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Run security assessment on a codebase.

    Scans the codebase, generates SECURITY.md, and stores it as an artifact.

    Args:
        path: Absolute path to the codebase.
        force: If True, overwrite existing SECURITY.md artifact.

    Returns:
        Dictionary with assessment summary or error.
    """
    # Validate path
    error = _validate_path(path)
    if error:
        return error

    project_path = Path(path)
    manager = ScanStateManager(project_path)

    # Check if artifact already exists
    if not force and manager.artifact_exists("SECURITY.md"):
        return {
            "error": False,
            "skipped": True,
            "message": "SECURITY.md already exists. Use force=True to overwrite.",
            "path": path,
        }

    # Scan the codebase
    scanner = CodebaseScanner(project_path)
    scan_result = scanner.scan()

    # Generate SECURITY.md
    generator = SecurityDocGenerator(scan_result)
    security_doc = generator.generate()

    # Store the artifact
    manager.write_artifact("SECURITY.md", security_doc)

    return {
        "error": False,
        "path": path,
        "file_count": scan_result.file_count,
        "languages": scan_result.languages,
        "language_stats": scan_result.language_stats,
        "frameworks": scan_result.frameworks,
        "artifact": "SECURITY.md",
        "artifact_size": len(security_doc),
    }


async def run_threat_modeling(
    path: str,
    focus_components: list[str] | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Run STRIDE threat analysis on documented architecture.

    Reads SECURITY.md artifact and performs threat modeling using STRIDE
    methodology, generating THREAT_MODEL.json artifact.

    Args:
        path: Absolute path to the codebase.
        focus_components: Optional list of component names to analyze.

    Returns:
        Dictionary with analysis results or error information.
    """
    # Validate path
    validation_error = _validate_path(path)
    if validation_error:
        return validation_error

    # Run threat modeling
    handler = ThreatModelingHandler()
    result = handler.run(path, focus_components=focus_components)

    # Convert handler result to standard response format
    if result["status"] == "error":
        return {
            "error": True,
            "code": "DEPENDENCY_ERROR",
            "message": result["message"],
            "path": path,
        }

    return {
        "error": False,
        "path": path,
        "threats_identified": result["threats_identified"],
        "components_analyzed": result["components_analyzed"],
        "artifact": "THREAT_MODEL.json",
        "artifact_path": result["artifact_path"],
        "summary": result["summary"],
        "invalid_components": result.get("invalid_components", []),
    }


async def run_code_review(
    path: str,
    focus_components: list[str] | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Run code review analysis for vulnerability detection.

    Reads THREAT_MODEL.json artifact and scans code for vulnerability
    patterns, generating VULNERABILITIES.json artifact.

    Args:
        path: Absolute path to the codebase.
        focus_components: Optional list of component paths to focus on.

    Returns:
        Dictionary with analysis results or error information.
    """
    # Validate path
    validation_error = _validate_path(path)
    if validation_error:
        return validation_error

    # Run code review
    handler = CodeReviewHandler()
    result = handler.run(path, focus_components=focus_components)

    # Convert handler result to standard response format
    if result["status"] == "error":
        return {
            "error": True,
            "code": "DEPENDENCY_ERROR",
            "message": result["message"],
            "path": path,
        }

    return {
        "error": False,
        "path": path,
        "vulnerabilities_found": result["vulnerabilities_found"],
        "threats_analyzed": result["threats_analyzed"],
        "not_confirmed": result["not_confirmed"],
        "artifact": "VULNERABILITIES.json",
        "artifact_path": result["artifact_path"],
        "summary": result["summary"],
        "focus_components": result.get("focus_components", []),
    }


async def run_dast(
    path: str,
    target_url: str,
    vulnerability_ids: list[str] | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Run DAST testing on confirmed vulnerabilities.

    Reads VULNERABILITIES.json artifact and tests each confirmed vulnerability
    against the running application, generating DAST_VALIDATION.json artifact.

    Args:
        path: Absolute path to the codebase.
        target_url: Base URL of the running target application.
        vulnerability_ids: Optional list of specific vulnerability IDs to test.

    Returns:
        Dictionary with test results or error information.
    """
    # Validate path
    validation_error = _validate_path(path)
    if validation_error:
        return validation_error

    # Run DAST testing
    handler = DASTHandler()
    result = await handler.run(
        project_path=Path(path),
        target_url=target_url,
        vulnerability_ids=vulnerability_ids,
    )

    # Convert handler result to standard response format
    if result["status"] == "error":
        return {
            "error": True,
            "code": "DAST_ERROR",
            "message": result["message"],
            "path": path,
        }

    return {
        "error": False,
        "path": path,
        "target_url": target_url,
        "tested": result["tested"],
        "exploitable": result["exploitable"],
        "not_exploitable": result["not_exploitable"],
        "by_severity": result.get("by_severity", {}),
        "artifact": result.get("artifact", "DAST_VALIDATION.json"),
        "message": result["message"],
    }


async def generate_report(
    path: str,
    format: str = "both",
    **_kwargs: Any,
) -> dict[str, Any]:
    """Generate security report from scan artifacts.

    Reads all available artifacts and generates comprehensive JSON and/or
    Markdown reports.

    Args:
        path: Absolute path to the codebase.
        format: Output format - "json", "markdown", or "both".

    Returns:
        Dictionary with report generation results or error information.
    """
    # Validate path
    validation_error = _validate_path(path)
    if validation_error:
        return validation_error

    # Validate format
    valid_formats = ("json", "markdown", "both")
    if format not in valid_formats:
        return {
            "error": True,
            "code": "INVALID_FORMAT",
            "message": f"Invalid format: {format}. Must be one of: {valid_formats}",
            "path": path,
        }

    # Generate report
    handler = ReportHandler()
    result = handler.run(
        project_path=Path(path),
        format=format,
    )

    # Convert handler result to standard response format
    if result["status"] == "error":
        return {
            "error": True,
            "code": "REPORT_ERROR",
            "message": result["message"],
            "path": path,
        }

    return {
        "error": False,
        "path": path,
        "format": format,
        "artifacts": result["artifacts"],
        "summary": result["summary"],
        "message": result["message"],
    }


# Severity ordering for filtering (lower index = more severe)
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


async def get_vulnerabilities(
    path: str,
    severity: str | None = None,
    cwe_id: str | None = None,
    file_path: str | None = None,
    limit: int = 10,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Get filtered vulnerability data from VULNERABILITIES.json.

    Args:
        path: Absolute path to the codebase.
        severity: Filter by minimum severity level (critical, high, medium, low).
        cwe_id: Filter by specific CWE ID (e.g., "CWE-89").
        file_path: Filter by file path pattern (substring match).
        limit: Maximum number of results to return.

    Returns:
        Dictionary with filtered vulnerabilities or error information.
    """
    from securevibes_mcp.agents.vulnerability_reader import VulnerabilityReader

    # Validate path
    validation_error = _validate_path(path)
    if validation_error:
        return validation_error

    project_path = Path(path)
    reader = VulnerabilityReader(root_path=project_path)

    # Read vulnerabilities
    data = reader.read()
    if data is None:
        return {
            "error": True,
            "code": "ARTIFACT_NOT_FOUND",
            "message": "VULNERABILITIES.json not found. Run code review first.",
            "path": path,
        }

    vulnerabilities = data.get("vulnerabilities", [])

    # Filter by minimum severity
    if severity:
        if severity not in SEVERITY_ORDER:
            return {
                "error": True,
                "code": "INVALID_SEVERITY",
                "message": f"Invalid severity: {severity}. Must be one of: {SEVERITY_ORDER}",
                "path": path,
            }
        severity_threshold = SEVERITY_ORDER.index(severity)
        vulnerabilities = [
            v for v in vulnerabilities
            if SEVERITY_ORDER.index(v.get("severity", "low")) <= severity_threshold
        ]

    # Filter by CWE ID
    if cwe_id:
        vulnerabilities = [
            v for v in vulnerabilities
            if v.get("cwe_id") == cwe_id
        ]

    # Filter by file path pattern
    if file_path:
        vulnerabilities = [
            v for v in vulnerabilities
            if v.get("file_path") and file_path in v.get("file_path", "")
        ]

    # Sort by severity (most severe first)
    vulnerabilities.sort(
        key=lambda v: SEVERITY_ORDER.index(v.get("severity", "low"))
    )

    # Apply limit
    total_count = len(vulnerabilities)
    vulnerabilities = vulnerabilities[:limit]

    return {
        "error": False,
        "path": path,
        "total_count": total_count,
        "returned_count": len(vulnerabilities),
        "filters_applied": {
            "severity": severity,
            "cwe_id": cwe_id,
            "file_path": file_path,
            "limit": limit,
        },
        "vulnerabilities": vulnerabilities,
    }
