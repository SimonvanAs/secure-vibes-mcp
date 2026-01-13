"""Tests for DAST handler."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestDASTHandler:
    """Tests for DASTHandler class."""

    def test_handler_creation(self):
        """Test that DASTHandler can be created."""
        from securevibes_mcp.agents.dast_handler import DASTHandler

        handler = DASTHandler()
        assert handler is not None

    @pytest.mark.asyncio
    async def test_handler_requires_vulnerabilities_json(self, tmp_path: Path):
        """Test that handler fails without VULNERABILITIES.json."""
        from securevibes_mcp.agents.dast_handler import DASTHandler

        handler = DASTHandler()
        result = await handler.run(
            project_path=tmp_path,
            target_url="http://localhost:8080",
        )

        assert result["status"] == "error"
        assert "VULNERABILITIES.json" in result["message"]

    @pytest.mark.asyncio
    async def test_handler_runs_with_valid_artifact(self, tmp_path: Path):
        """Test that handler runs when VULNERABILITIES.json exists."""
        from securevibes_mcp.agents.dast_handler import DASTHandler

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
                }
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        handler = DASTHandler()

        # Mock the tester to avoid real HTTP calls
        with patch(
            "securevibes_mcp.agents.dast_handler.DASTTester"
        ) as mock_tester_class:
            mock_tester = MagicMock()
            mock_tester_class.return_value = mock_tester

            # Mock test_vulnerability to return a result
            from securevibes_mcp.agents.dast_tester import TestResult

            mock_tester.test_vulnerability = AsyncMock(
                return_value=TestResult(
                    vulnerability_id="VULN-001",
                    exploitable=True,
                    evidence="SQL error detected",
                    http_status=500,
                    response_time_ms=150.0,
                    test_payload="' OR '1'='1",
                    notes="Confirmed",
                )
            )

            result = await handler.run(
                project_path=tmp_path,
                target_url="http://localhost:8080",
            )

        assert result["status"] == "success"
        assert result["tested"] == 1
        assert result["exploitable"] == 1

    @pytest.mark.asyncio
    async def test_handler_filters_by_vulnerability_ids(self, tmp_path: Path):
        """Test that handler filters by specific vulnerability IDs."""
        from securevibes_mcp.agents.dast_handler import DASTHandler

        # Create VULNERABILITIES.json artifact with multiple vulns
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
                {
                    "id": "VULN-003",
                    "status": "confirmed",
                    "cwe_id": "CWE-78",
                    "severity": "critical",
                },
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        handler = DASTHandler()

        with patch(
            "securevibes_mcp.agents.dast_handler.DASTTester"
        ) as mock_tester_class:
            mock_tester = MagicMock()
            mock_tester_class.return_value = mock_tester

            from securevibes_mcp.agents.dast_tester import TestResult

            mock_tester.test_vulnerability = AsyncMock(
                return_value=TestResult(
                    vulnerability_id="VULN-001",
                    exploitable=False,
                    evidence="Not exploitable",
                )
            )

            result = await handler.run(
                project_path=tmp_path,
                target_url="http://localhost:8080",
                vulnerability_ids=["VULN-001", "VULN-003"],
            )

        # Should only test 2 vulnerabilities
        assert result["tested"] == 2

    @pytest.mark.asyncio
    async def test_handler_writes_output_artifact(self, tmp_path: Path):
        """Test that handler writes DAST_VALIDATION.json artifact."""
        from securevibes_mcp.agents.dast_handler import DASTHandler

        # Create VULNERABILITIES.json artifact
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
                }
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        handler = DASTHandler()

        with patch(
            "securevibes_mcp.agents.dast_handler.DASTTester"
        ) as mock_tester_class:
            mock_tester = MagicMock()
            mock_tester_class.return_value = mock_tester

            from securevibes_mcp.agents.dast_tester import TestResult

            mock_tester.test_vulnerability = AsyncMock(
                return_value=TestResult(
                    vulnerability_id="VULN-001",
                    exploitable=True,
                    evidence="SQL error",
                )
            )

            await handler.run(
                project_path=tmp_path,
                target_url="http://localhost:8080",
            )

        # Check output artifact exists
        output_path = securevibes_dir / "DAST_VALIDATION.json"
        assert output_path.exists()

        # Verify content
        data = json.loads(output_path.read_text())
        assert data["target_url"] == "http://localhost:8080"
        assert len(data["validations"]) == 1
        assert data["validations"][0]["vulnerability_id"] == "VULN-001"


class TestDASTHandlerEdgeCases:
    """Tests for edge cases in DAST handler."""

    @pytest.mark.asyncio
    async def test_handler_with_no_confirmed_vulnerabilities(self, tmp_path: Path):
        """Test handler when no vulnerabilities are confirmed."""
        from securevibes_mcp.agents.dast_handler import DASTHandler

        # Create VULNERABILITIES.json with only unconfirmed vulns
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {
                    "id": "VULN-001",
                    "status": "not_confirmed",
                    "cwe_id": "CWE-89",
                    "severity": "critical",
                }
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        handler = DASTHandler()
        result = await handler.run(
            project_path=tmp_path,
            target_url="http://localhost:8080",
        )

        assert result["status"] == "success"
        assert result["tested"] == 0
        assert "no confirmed vulnerabilities" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_handler_with_http_error(self, tmp_path: Path):
        """Test handler handles HTTP errors gracefully."""
        from securevibes_mcp.agents.dast_handler import DASTHandler

        # Create VULNERABILITIES.json
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
                }
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        handler = DASTHandler()

        with patch(
            "securevibes_mcp.agents.dast_handler.DASTTester"
        ) as mock_tester_class:
            mock_tester = MagicMock()
            mock_tester_class.return_value = mock_tester

            # Simulate HTTP error
            import httpx

            mock_tester.test_vulnerability = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )

            result = await handler.run(
                project_path=tmp_path,
                target_url="http://localhost:8080",
            )

        # Should handle error gracefully
        assert result["status"] == "error"
        assert "connection" in result["message"].lower()
