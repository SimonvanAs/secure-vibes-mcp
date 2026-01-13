"""Report output structures and writer."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securevibes_mcp.storage import ScanStateManager


@dataclass
class ReportSummary:
    """Summary statistics for a security scan report."""

    components_analyzed: int = 0
    threats_identified: int = 0
    vulnerabilities_found: int = 0
    vulnerabilities_confirmed: int = 0
    vulnerabilities_exploitable: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_cwe: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all summary fields.
        """
        return {
            "components_analyzed": self.components_analyzed,
            "threats_identified": self.threats_identified,
            "vulnerabilities_found": self.vulnerabilities_found,
            "vulnerabilities_confirmed": self.vulnerabilities_confirmed,
            "vulnerabilities_exploitable": self.vulnerabilities_exploitable,
            "by_severity": self.by_severity,
            "by_cwe": self.by_cwe,
        }


@dataclass
class ScanReport:
    """Complete security scan report."""

    summary: ReportSummary
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    threats: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    version: str = "1.0.0"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all report fields.
        """
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "summary": self.summary.to_dict(),
            "vulnerabilities": self.vulnerabilities,
            "threats": self.threats,
            "recommendations": self.recommendations,
        }

    def to_json(self) -> str:
        """Convert to JSON string.

        Returns:
            JSON string representation.
        """
        return json.dumps(self.to_dict(), indent=2)


class MarkdownReportGenerator:
    """Generates Markdown reports from ScanReport."""

    def generate(self, report: ScanReport) -> str:
        """Generate a Markdown report.

        Args:
            report: The scan report to convert to Markdown.

        Returns:
            Markdown formatted string.
        """
        lines: list[str] = []

        # Title
        lines.append("# Security Scan Report")
        lines.append("")
        lines.append(f"Generated: {report.generated_at}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Components Analyzed:** {report.summary.components_analyzed}")
        lines.append(f"- **Threats Identified:** {report.summary.threats_identified}")
        lines.append(
            f"- **Vulnerabilities Found:** {report.summary.vulnerabilities_found} "
            f"({report.summary.vulnerabilities_confirmed} confirmed, "
            f"{report.summary.vulnerabilities_exploitable} exploitable)"
        )
        lines.append("")

        # Severity Breakdown
        if report.summary.by_severity:
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for severity in ["critical", "high", "medium", "low"]:
                count = report.summary.by_severity.get(severity, 0)
                if count > 0:
                    lines.append(f"| {severity.capitalize()} | {count} |")
            lines.append("")

        # Critical Findings
        critical_vulns = [
            v for v in report.vulnerabilities if v.get("severity") == "critical"
        ]
        if critical_vulns:
            lines.append("## Critical Findings")
            lines.append("")
            for vuln in critical_vulns:
                lines.extend(self._format_vulnerability(vuln))
            lines.append("")

        # High Findings
        high_vulns = [
            v for v in report.vulnerabilities if v.get("severity") == "high"
        ]
        if high_vulns:
            lines.append("## High Severity Findings")
            lines.append("")
            for vuln in high_vulns:
                lines.extend(self._format_vulnerability(vuln))
            lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(report.recommendations, 1):
                priority = rec.get("priority", "medium").capitalize()
                title = rec.get("title", "Recommendation")
                description = rec.get("description", "")
                lines.append(f"### {i}. {title} ({priority})")
                lines.append("")
                if description:
                    lines.append(description)
                    lines.append("")

        # All Vulnerabilities
        if report.vulnerabilities:
            lines.append("## All Vulnerabilities")
            lines.append("")
            lines.append("| ID | Severity | CWE | File | Exploitable |")
            lines.append("|----|----------|-----|------|-------------|")
            for vuln in report.vulnerabilities:
                vuln_id = vuln.get("id", "N/A")
                severity = vuln.get("severity", "N/A")
                cwe = vuln.get("cwe_id", "N/A")
                file_path = vuln.get("file_path", "N/A")
                exploitable = "Yes" if vuln.get("exploitable") else "No"
                lines.append(f"| {vuln_id} | {severity} | {cwe} | {file_path} | {exploitable} |")
            lines.append("")

        return "\n".join(lines)

    def _format_vulnerability(self, vuln: dict[str, Any]) -> list[str]:
        """Format a single vulnerability for Markdown.

        Args:
            vuln: Vulnerability dictionary.

        Returns:
            List of Markdown lines.
        """
        lines: list[str] = []
        vuln_id = vuln.get("id", "UNKNOWN")
        description = vuln.get("description", "No description")
        lines.append(f"### {vuln_id}: {description}")
        lines.append("")

        file_path = vuln.get("file_path", "N/A")
        line_number = vuln.get("line_number", "")
        if line_number:
            lines.append(f"- **File:** {file_path}:{line_number}")
        else:
            lines.append(f"- **File:** {file_path}")

        cwe = vuln.get("cwe_id")
        if cwe:
            lines.append(f"- **CWE:** {cwe}")

        exploitable = vuln.get("exploitable")
        if exploitable is not None:
            lines.append(f"- **Exploitable:** {'Yes' if exploitable else 'No'}")

        lines.append("")
        return lines


class ReportWriter:
    """Writer for report artifacts."""

    JSON_ARTIFACT_NAME = "scan_results.json"
    MD_ARTIFACT_NAME = "scan_report.md"

    def __init__(self, root_path: Path) -> None:
        """Initialize the writer.

        Args:
            root_path: Root path of the project.
        """
        self.root_path = root_path
        self.storage = ScanStateManager(root_path)
        self.markdown_generator = MarkdownReportGenerator()

    def write_json(self, report: ScanReport) -> None:
        """Write the scan_results.json artifact.

        Args:
            report: The scan report to write.
        """
        content = report.to_json()
        self.storage.write_artifact(self.JSON_ARTIFACT_NAME, content)

    def write_markdown(self, report: ScanReport) -> None:
        """Write the scan_report.md artifact.

        Args:
            report: The scan report to write.
        """
        content = self.markdown_generator.generate(report)
        self.storage.write_artifact(self.MD_ARTIFACT_NAME, content)

    def write_both(self, report: ScanReport) -> None:
        """Write both JSON and Markdown artifacts.

        Args:
            report: The scan report to write.
        """
        self.write_json(report)
        self.write_markdown(report)
