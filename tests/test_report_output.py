"""Tests for report output structures."""

import json
from pathlib import Path

import pytest


class TestReportSummary:
    """Tests for ReportSummary dataclass."""

    def test_summary_creation(self):
        """Test that ReportSummary can be created."""
        from securevibes_mcp.agents.report_output import ReportSummary

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
        )

        assert summary.components_analyzed == 5
        assert summary.threats_identified == 12
        assert summary.vulnerabilities_found == 8
        assert summary.vulnerabilities_confirmed == 5
        assert summary.vulnerabilities_exploitable == 2

    def test_summary_to_dict(self):
        """Test that ReportSummary can be converted to dict."""
        from securevibes_mcp.agents.report_output import ReportSummary

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
            by_severity={"critical": 2, "high": 3},
            by_cwe={"CWE-89": 2},
        )

        data = summary.to_dict()

        assert data["components_analyzed"] == 5
        assert data["by_severity"]["critical"] == 2
        assert data["by_cwe"]["CWE-89"] == 2


class TestScanReport:
    """Tests for ScanReport dataclass."""

    def test_report_creation(self):
        """Test that ScanReport can be created."""
        from securevibes_mcp.agents.report_output import ReportSummary, ScanReport

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
        )

        report = ScanReport(summary=summary)

        assert report is not None
        assert report.summary.components_analyzed == 5
        assert report.version == "1.0.0"

    def test_report_to_dict(self):
        """Test that ScanReport can be converted to dict."""
        from securevibes_mcp.agents.report_output import ReportSummary, ScanReport

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
        )

        report = ScanReport(
            summary=summary,
            vulnerabilities=[{"id": "VULN-001", "severity": "critical"}],
            threats=[{"id": "THREAT-001", "category": "Spoofing"}],
            recommendations=[{"priority": "critical", "title": "Fix SQL injection"}],
        )

        data = report.to_dict()

        assert data["version"] == "1.0.0"
        assert "generated_at" in data
        assert data["summary"]["components_analyzed"] == 5
        assert len(data["vulnerabilities"]) == 1
        assert len(data["threats"]) == 1
        assert len(data["recommendations"]) == 1

    def test_report_to_json(self):
        """Test that ScanReport can be converted to JSON."""
        from securevibes_mcp.agents.report_output import ReportSummary, ScanReport

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
        )

        report = ScanReport(summary=summary)

        json_str = report.to_json()

        # Should be valid JSON
        data = json.loads(json_str)
        assert data["version"] == "1.0.0"


class TestMarkdownReportGenerator:
    """Tests for MarkdownReportGenerator class."""

    def test_generator_creation(self):
        """Test that MarkdownReportGenerator can be created."""
        from securevibes_mcp.agents.report_output import MarkdownReportGenerator

        generator = MarkdownReportGenerator()
        assert generator is not None

    def test_generator_produces_markdown(self):
        """Test that generator produces Markdown content."""
        from securevibes_mcp.agents.report_output import (
            MarkdownReportGenerator,
            ReportSummary,
            ScanReport,
        )

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
            by_severity={"critical": 2, "high": 3, "medium": 2, "low": 1},
        )

        report = ScanReport(summary=summary)
        generator = MarkdownReportGenerator()
        markdown = generator.generate(report)

        assert "# Security Scan Report" in markdown
        assert "Executive Summary" in markdown
        assert "Components Analyzed" in markdown

    def test_generator_includes_vulnerabilities(self):
        """Test that generator includes vulnerability details."""
        from securevibes_mcp.agents.report_output import (
            MarkdownReportGenerator,
            ReportSummary,
            ScanReport,
        )

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=1,
            vulnerabilities_found=1,
            vulnerabilities_confirmed=1,
            vulnerabilities_exploitable=1,
        )

        report = ScanReport(
            summary=summary,
            vulnerabilities=[
                {
                    "id": "VULN-001",
                    "severity": "critical",
                    "cwe_id": "CWE-89",
                    "file_path": "/app/db.py",
                    "line_number": 45,
                    "description": "SQL Injection",
                    "exploitable": True,
                }
            ],
        )

        generator = MarkdownReportGenerator()
        markdown = generator.generate(report)

        assert "VULN-001" in markdown
        assert "SQL Injection" in markdown
        assert "CWE-89" in markdown

    def test_generator_includes_recommendations(self):
        """Test that generator includes recommendations."""
        from securevibes_mcp.agents.report_output import (
            MarkdownReportGenerator,
            ReportSummary,
            ScanReport,
        )

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=1,
            vulnerabilities_found=1,
            vulnerabilities_confirmed=1,
            vulnerabilities_exploitable=0,
        )

        report = ScanReport(
            summary=summary,
            recommendations=[
                {
                    "priority": "critical",
                    "title": "Fix SQL Injection vulnerabilities",
                    "description": "Use parameterized queries instead of string concatenation.",
                }
            ],
        )

        generator = MarkdownReportGenerator()
        markdown = generator.generate(report)

        assert "Recommendations" in markdown
        assert "Fix SQL Injection" in markdown


class TestReportWriter:
    """Tests for ReportWriter class."""

    def test_writer_creation(self, tmp_path: Path):
        """Test that ReportWriter can be created."""
        from securevibes_mcp.agents.report_output import ReportWriter

        writer = ReportWriter(root_path=tmp_path)
        assert writer is not None

    def test_writer_writes_json(self, tmp_path: Path):
        """Test that writer writes scan_results.json."""
        from securevibes_mcp.agents.report_output import (
            ReportSummary,
            ReportWriter,
            ScanReport,
        )

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
        )

        report = ScanReport(summary=summary)

        writer = ReportWriter(root_path=tmp_path)
        writer.write_json(report)

        artifact_path = tmp_path / ".securevibes" / "scan_results.json"
        assert artifact_path.exists()

        data = json.loads(artifact_path.read_text())
        assert data["summary"]["components_analyzed"] == 5

    def test_writer_writes_markdown(self, tmp_path: Path):
        """Test that writer writes scan_report.md."""
        from securevibes_mcp.agents.report_output import (
            ReportSummary,
            ReportWriter,
            ScanReport,
        )

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
        )

        report = ScanReport(summary=summary)

        writer = ReportWriter(root_path=tmp_path)
        writer.write_markdown(report)

        artifact_path = tmp_path / ".securevibes" / "scan_report.md"
        assert artifact_path.exists()

        content = artifact_path.read_text()
        assert "Security Scan Report" in content

    def test_writer_writes_both(self, tmp_path: Path):
        """Test that writer writes both artifacts."""
        from securevibes_mcp.agents.report_output import (
            ReportSummary,
            ReportWriter,
            ScanReport,
        )

        summary = ReportSummary(
            components_analyzed=5,
            threats_identified=12,
            vulnerabilities_found=8,
            vulnerabilities_confirmed=5,
            vulnerabilities_exploitable=2,
        )

        report = ScanReport(summary=summary)

        writer = ReportWriter(root_path=tmp_path)
        writer.write_both(report)

        json_path = tmp_path / ".securevibes" / "scan_results.json"
        md_path = tmp_path / ".securevibes" / "scan_report.md"

        assert json_path.exists()
        assert md_path.exists()
