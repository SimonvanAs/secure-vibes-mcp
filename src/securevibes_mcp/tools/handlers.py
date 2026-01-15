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
    include_suppressed: bool = False,
    limit: int = 10,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Get filtered vulnerability data from VULNERABILITIES.json.

    Args:
        path: Absolute path to the codebase.
        severity: Filter by minimum severity level (critical, high, medium, low).
        cwe_id: Filter by specific CWE ID (e.g., "CWE-89").
        file_path: Filter by file path pattern (substring match).
        include_suppressed: Include suppressed vulnerabilities in results.
        limit: Maximum number of results to return.

    Returns:
        Dictionary with filtered vulnerabilities or error information.
    """
    from securevibes_mcp.agents.suppression_reader import SuppressionReader
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

    # Filter out suppressed vulnerabilities unless include_suppressed is True
    suppressed_count = 0
    if not include_suppressed:
        suppression_reader = SuppressionReader(project_path)
        original_count = len(vulnerabilities)
        vulnerabilities = [
            v for v in vulnerabilities
            if not suppression_reader.is_suppressed(v)
        ]
        suppressed_count = original_count - len(vulnerabilities)

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
        "suppressed_count": suppressed_count,
        "filters_applied": {
            "severity": severity,
            "cwe_id": cwe_id,
            "file_path": file_path,
            "include_suppressed": include_suppressed,
            "limit": limit,
        },
        "vulnerabilities": vulnerabilities,
    }


async def suppress_vulnerability(
    path: str,
    vuln_id: str | None = None,
    file_pattern: str | None = None,
    cwe_id: str | None = None,
    reason: str = "false_positive",
    justification: str = "",
    **_kwargs: Any,
) -> dict[str, Any]:
    """Suppress a vulnerability or pattern of vulnerabilities.

    Args:
        path: Absolute path to the codebase.
        vuln_id: Specific vulnerability ID to suppress (e.g., "VULN-001").
        file_pattern: File path pattern to suppress (substring match).
        cwe_id: CWE ID to suppress all vulnerabilities of this type.
        reason: Reason for suppression (false_positive, acceptable_risk, will_not_fix, mitigated).
        justification: Detailed justification for the suppression.

    Returns:
        Dictionary with created suppression or error information.
    """
    from securevibes_mcp.agents.suppression_writer import SuppressionWriter

    # Validate path
    validation_error = _validate_path(path)
    if validation_error:
        return validation_error

    # Determine suppression type
    if vuln_id:
        suppression_type = "vuln_id"
    elif file_pattern:
        suppression_type = "file_pattern"
    elif cwe_id:
        suppression_type = "cwe_pattern"
    else:
        return {
            "error": True,
            "code": "MISSING_TARGET",
            "message": "Must specify one of: vuln_id, file_pattern, or cwe_id",
            "path": path,
        }

    project_path = Path(path)
    writer = SuppressionWriter(project_path)

    try:
        suppression = writer.add(
            suppression_type=suppression_type,
            vuln_id=vuln_id,
            pattern=file_pattern,
            cwe_id=cwe_id,
            reason=reason,
            justification=justification,
        )
        return {
            "error": False,
            "message": f"Created suppression {suppression.id}",
            "suppression": suppression.to_dict(),
            "path": path,
        }
    except ValueError as e:
        return {
            "error": True,
            "code": "INVALID_INPUT",
            "message": str(e),
            "path": path,
        }


async def remove_suppression(
    path: str,
    suppression_id: str,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Remove a suppression by ID.

    Args:
        path: Absolute path to the codebase.
        suppression_id: The suppression ID to remove (e.g., "SUPP-001").

    Returns:
        Dictionary with removal status or error information.
    """
    from securevibes_mcp.agents.suppression_writer import SuppressionWriter

    # Validate path
    validation_error = _validate_path(path)
    if validation_error:
        return validation_error

    project_path = Path(path)
    writer = SuppressionWriter(project_path)

    if writer.remove(suppression_id):
        return {
            "error": False,
            "message": f"Removed suppression {suppression_id}",
            "suppression_id": suppression_id,
            "path": path,
        }
    else:
        return {
            "error": True,
            "code": "NOT_FOUND",
            "message": f"Suppression {suppression_id} not found",
            "suppression_id": suppression_id,
            "path": path,
        }


async def list_suppressions(
    path: str,
    include_expired: bool = False,
    **_kwargs: Any,
) -> dict[str, Any]:
    """List all suppressions for a project.

    Args:
        path: Absolute path to the codebase.
        include_expired: Include expired suppressions.

    Returns:
        Dictionary with list of suppressions or error information.
    """
    from securevibes_mcp.agents.suppression_reader import SuppressionReader

    # Validate path
    validation_error = _validate_path(path)
    if validation_error:
        return validation_error

    project_path = Path(path)
    reader = SuppressionReader(project_path)

    suppressions = reader.get_suppressions(include_expired=include_expired)

    return {
        "error": False,
        "path": path,
        "total_count": len(suppressions),
        "include_expired": include_expired,
        "suppressions": [s.to_dict() for s in suppressions],
    }
