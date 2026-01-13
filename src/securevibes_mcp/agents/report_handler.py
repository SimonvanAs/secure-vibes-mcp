"""Report handler for generating security reports."""

from pathlib import Path
from typing import Any

from securevibes_mcp.agents.artifact_readers import (
    DASTValidationReader,
    SecurityDocReader,
)
from securevibes_mcp.agents.report_output import (
    ReportSummary,
    ReportWriter,
    ScanReport,
)
from securevibes_mcp.agents.threat_model_reader import ThreatModelReader
from securevibes_mcp.agents.vulnerability_reader import VulnerabilityReader


# CWE-based recommendations
CWE_RECOMMENDATIONS: dict[str, dict[str, str]] = {
    "CWE-89": {
        "title": "Fix SQL Injection vulnerabilities",
        "description": (
            "Use parameterized queries or prepared statements instead of "
            "string concatenation. Consider using an ORM that handles "
            "escaping automatically."
        ),
    },
    "CWE-79": {
        "title": "Fix Cross-Site Scripting (XSS) vulnerabilities",
        "description": (
            "Sanitize and encode all user input before rendering in HTML. "
            "Use context-aware output encoding and Content Security Policy headers."
        ),
    },
    "CWE-78": {
        "title": "Fix Command Injection vulnerabilities",
        "description": (
            "Avoid passing user input to shell commands. Use language-specific "
            "APIs instead of shell execution. If shell is required, use allowlists "
            "for permitted values."
        ),
    },
    "CWE-22": {
        "title": "Fix Path Traversal vulnerabilities",
        "description": (
            "Validate and sanitize file paths. Use allowlists for permitted "
            "directories. Resolve paths and verify they remain within expected bounds."
        ),
    },
    "CWE-502": {
        "title": "Fix Insecure Deserialization vulnerabilities",
        "description": (
            "Avoid deserializing untrusted data. Use safe serialization formats "
            "like JSON. Implement integrity checks and type validation."
        ),
    },
}


class ReportHandler:
    """Handler for generating security reports.

    Aggregates findings from all security pipeline stages and generates
    comprehensive JSON and Markdown reports.
    """

    def __init__(self) -> None:
        """Initialize the handler."""
        pass

    def run(
        self,
        project_path: Path,
        format: str = "both",
    ) -> dict[str, Any]:
        """Generate security report from available artifacts.

        Args:
            project_path: Path to the project root.
            format: Output format - "json", "markdown", or "both".

        Returns:
            Dictionary with status and summary information.
        """
        # Initialize readers
        security_reader = SecurityDocReader(root_path=project_path)
        threat_reader = ThreatModelReader(root_path=project_path)
        vuln_reader = VulnerabilityReader(root_path=project_path)
        dast_reader = DASTValidationReader(root_path=project_path)

        # Read available artifacts
        vulnerabilities = self._read_vulnerabilities(vuln_reader)
        threats = self._read_threats(threat_reader)
        exploitable_ids = dast_reader.get_exploitable_ids()

        # Mark vulnerabilities as exploitable based on DAST results
        for vuln in vulnerabilities:
            vuln["exploitable"] = vuln.get("id") in exploitable_ids

        # Calculate statistics
        summary = self._calculate_summary(vulnerabilities, threats)

        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities)

        # Build report
        report = ScanReport(
            summary=summary,
            vulnerabilities=vulnerabilities,
            threats=threats,
            recommendations=recommendations,
        )

        # Write artifacts based on format
        writer = ReportWriter(root_path=project_path)
        artifacts: list[str] = []

        if format in ("json", "both"):
            writer.write_json(report)
            artifacts.append("scan_results.json")

        if format in ("markdown", "both"):
            writer.write_markdown(report)
            artifacts.append("scan_report.md")

        return {
            "status": "success",
            "message": f"Generated report with {len(vulnerabilities)} vulnerabilities",
            "artifacts": artifacts,
            "summary": summary.to_dict(),
        }

    def _read_vulnerabilities(
        self, reader: VulnerabilityReader
    ) -> list[dict[str, Any]]:
        """Read vulnerabilities from artifact.

        Args:
            reader: VulnerabilityReader instance.

        Returns:
            List of vulnerability dicts.
        """
        data = reader.read()
        if data is None:
            return []
        return data.get("vulnerabilities", [])

    def _read_threats(self, reader: ThreatModelReader) -> list[dict[str, Any]]:
        """Read threats from artifact.

        Args:
            reader: ThreatModelReader instance.

        Returns:
            List of threat dicts.
        """
        data = reader.read()
        if data is None:
            return []
        return data.get("threats", [])

    def _calculate_summary(
        self,
        vulnerabilities: list[dict[str, Any]],
        threats: list[dict[str, Any]],
    ) -> ReportSummary:
        """Calculate summary statistics.

        Args:
            vulnerabilities: List of vulnerability dicts.
            threats: List of threat dicts.

        Returns:
            ReportSummary with calculated statistics.
        """
        # Count vulnerabilities by status
        confirmed = sum(
            1 for v in vulnerabilities if v.get("status") == "confirmed"
        )
        exploitable = sum(1 for v in vulnerabilities if v.get("exploitable"))

        # Count by severity
        by_severity: dict[str, int] = {}
        for v in vulnerabilities:
            severity = v.get("severity", "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1

        # Count by CWE
        by_cwe: dict[str, int] = {}
        for v in vulnerabilities:
            cwe = v.get("cwe_id")
            if cwe:
                by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

        # Count unique components from threats
        components = {t.get("component") for t in threats if t.get("component")}

        return ReportSummary(
            components_analyzed=len(components),
            threats_identified=len(threats),
            vulnerabilities_found=len(vulnerabilities),
            vulnerabilities_confirmed=confirmed,
            vulnerabilities_exploitable=exploitable,
            by_severity=by_severity,
            by_cwe=by_cwe,
        )

    def _generate_recommendations(
        self, vulnerabilities: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Generate recommendations based on findings.

        Args:
            vulnerabilities: List of vulnerability dicts.

        Returns:
            List of recommendation dicts.
        """
        recommendations: list[dict[str, Any]] = []
        seen_cwes: set[str] = set()

        # Sort vulnerabilities by severity for priority ordering
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "low"), 4),
        )

        for vuln in sorted_vulns:
            cwe = vuln.get("cwe_id")
            if cwe and cwe not in seen_cwes and cwe in CWE_RECOMMENDATIONS:
                seen_cwes.add(cwe)
                rec = CWE_RECOMMENDATIONS[cwe]

                # Find all vulnerabilities with this CWE
                affected = [
                    v.get("id") for v in vulnerabilities if v.get("cwe_id") == cwe
                ]

                recommendations.append({
                    "priority": vuln.get("severity", "medium"),
                    "title": rec["title"],
                    "description": rec["description"],
                    "affected_vulnerabilities": affected,
                })

        return recommendations
