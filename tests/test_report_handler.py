"""Tests for report handler."""

import json
from pathlib import Path

import pytest


class TestReportHandler:
    """Tests for ReportHandler class."""

    def test_handler_creation(self):
        """Test that ReportHandler can be created."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        handler = ReportHandler()
        assert handler is not None

    def test_handler_runs_with_no_artifacts(self, tmp_path: Path):
        """Test that handler runs gracefully with no artifacts."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        handler = ReportHandler()
        result = handler.run(project_path=tmp_path, format="both")

        assert result["status"] == "success"
        assert result["summary"]["vulnerabilities_found"] == 0

    def test_handler_runs_with_vulnerabilities(self, tmp_path: Path):
        """Test that handler processes VULNERABILITIES.json."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        # Create VULNERABILITIES.json artifact
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {
                    "id": "VULN-001",
                    "threat_id": "THREAT-001",
                    "status": "confirmed",
                    "cwe_id": "CWE-89",
                    "severity": "critical",
                    "file_path": "/app/db.py",
                    "line_number": 45,
                    "description": "SQL Injection",
                },
                {
                    "id": "VULN-002",
                    "threat_id": "THREAT-002",
                    "status": "not_confirmed",
                    "cwe_id": "CWE-79",
                    "severity": "high",
                    "file_path": "/app/views.py",
                    "line_number": 100,
                    "description": "XSS",
                },
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        handler = ReportHandler()
        result = handler.run(project_path=tmp_path, format="both")

        assert result["status"] == "success"
        assert result["summary"]["vulnerabilities_found"] == 2
        assert result["summary"]["vulnerabilities_confirmed"] == 1

    def test_handler_includes_dast_results(self, tmp_path: Path):
        """Test that handler includes DAST validation results."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        # Create artifacts
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {
                    "id": "VULN-001",
                    "status": "confirmed",
                    "cwe_id": "CWE-89",
                    "severity": "critical",
                },
                {
                    "id": "VULN-002",
                    "status": "confirmed",
                    "cwe_id": "CWE-79",
                    "severity": "high",
                },
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        dast_data = {
            "version": "1.0.0",
            "validations": [
                {"vulnerability_id": "VULN-001", "exploitable": True},
                {"vulnerability_id": "VULN-002", "exploitable": False},
            ],
        }
        (securevibes_dir / "DAST_VALIDATION.json").write_text(json.dumps(dast_data))

        handler = ReportHandler()
        result = handler.run(project_path=tmp_path, format="both")

        assert result["status"] == "success"
        assert result["summary"]["vulnerabilities_exploitable"] == 1

    def test_handler_writes_json_only(self, tmp_path: Path):
        """Test that handler writes only JSON when format=json."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        handler = ReportHandler()
        result = handler.run(project_path=tmp_path, format="json")

        assert result["status"] == "success"
        assert "scan_results.json" in result["artifacts"]
        assert "scan_report.md" not in result["artifacts"]

        json_path = tmp_path / ".securevibes" / "scan_results.json"
        md_path = tmp_path / ".securevibes" / "scan_report.md"
        assert json_path.exists()
        assert not md_path.exists()

    def test_handler_writes_markdown_only(self, tmp_path: Path):
        """Test that handler writes only Markdown when format=markdown."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        handler = ReportHandler()
        result = handler.run(project_path=tmp_path, format="markdown")

        assert result["status"] == "success"
        assert "scan_report.md" in result["artifacts"]
        assert "scan_results.json" not in result["artifacts"]

        json_path = tmp_path / ".securevibes" / "scan_results.json"
        md_path = tmp_path / ".securevibes" / "scan_report.md"
        assert not json_path.exists()
        assert md_path.exists()

    def test_handler_writes_both(self, tmp_path: Path):
        """Test that handler writes both when format=both."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        handler = ReportHandler()
        result = handler.run(project_path=tmp_path, format="both")

        assert result["status"] == "success"
        assert "scan_results.json" in result["artifacts"]
        assert "scan_report.md" in result["artifacts"]


class TestReportHandlerWithThreats:
    """Tests for report handler with threat model data."""

    def test_handler_includes_threats(self, tmp_path: Path):
        """Test that handler includes threats from THREAT_MODEL.json."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        # Create artifacts
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_data = {
            "version": "1.0.0",
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "Spoofing",
                    "component": "Auth",
                    "description": "Auth bypass",
                    "attack_vector": "Forged tokens",
                    "impact": "Full access",
                    "severity": "critical",
                },
                {
                    "id": "THREAT-002",
                    "category": "Tampering",
                    "component": "API",
                    "description": "SQL injection",
                    "attack_vector": "Malicious input",
                    "impact": "Data breach",
                    "severity": "high",
                },
            ],
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_data))

        handler = ReportHandler()
        result = handler.run(project_path=tmp_path, format="json")

        assert result["status"] == "success"
        assert result["summary"]["threats_identified"] == 2


class TestReportHandlerRecommendations:
    """Tests for report handler recommendations."""

    def test_handler_generates_recommendations(self, tmp_path: Path):
        """Test that handler generates recommendations based on findings."""
        from securevibes_mcp.agents.report_handler import ReportHandler

        # Create vulnerabilities artifact
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {
                    "id": "VULN-001",
                    "status": "confirmed",
                    "cwe_id": "CWE-89",
                    "severity": "critical",
                    "description": "SQL Injection",
                },
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        handler = ReportHandler()
        result = handler.run(project_path=tmp_path, format="json")

        # Read the generated JSON to check recommendations
        json_path = tmp_path / ".securevibes" / "scan_results.json"
        report_data = json.loads(json_path.read_text())

        # Should have at least one recommendation for critical vulnerability
        assert len(report_data["recommendations"]) > 0
