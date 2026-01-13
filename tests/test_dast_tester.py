"""Tests for DAST tester."""

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestPayloadGenerator:
    """Tests for PayloadGenerator class."""

    def test_generator_creation(self):
        """Test that PayloadGenerator can be created."""
        from securevibes_mcp.agents.dast_tester import PayloadGenerator

        generator = PayloadGenerator()
        assert generator is not None

    def test_generate_sql_injection_payloads(self):
        """Test generating SQL injection payloads."""
        from securevibes_mcp.agents.dast_tester import PayloadGenerator

        generator = PayloadGenerator()
        payloads = generator.get_payloads("CWE-89")

        assert len(payloads) > 0
        assert any("'" in p.value for p in payloads)
        assert all(p.cwe_id == "CWE-89" for p in payloads)

    def test_generate_xss_payloads(self):
        """Test generating XSS payloads."""
        from securevibes_mcp.agents.dast_tester import PayloadGenerator

        generator = PayloadGenerator()
        payloads = generator.get_payloads("CWE-79")

        assert len(payloads) > 0
        assert any("<script>" in p.value for p in payloads)

    def test_generate_command_injection_payloads(self):
        """Test generating command injection payloads."""
        from securevibes_mcp.agents.dast_tester import PayloadGenerator

        generator = PayloadGenerator()
        payloads = generator.get_payloads("CWE-78")

        assert len(payloads) > 0
        assert any(";" in p.value or "|" in p.value for p in payloads)

    def test_generate_path_traversal_payloads(self):
        """Test generating path traversal payloads."""
        from securevibes_mcp.agents.dast_tester import PayloadGenerator

        generator = PayloadGenerator()
        payloads = generator.get_payloads("CWE-22")

        assert len(payloads) > 0
        assert any("../" in p.value for p in payloads)

    def test_unknown_cwe_returns_generic_payloads(self):
        """Test that unknown CWE returns generic payloads."""
        from securevibes_mcp.agents.dast_tester import PayloadGenerator

        generator = PayloadGenerator()
        payloads = generator.get_payloads("CWE-99999")

        assert len(payloads) > 0  # Should return generic payloads


class TestTestPayload:
    """Tests for TestPayload dataclass."""

    def test_payload_creation(self):
        """Test that TestPayload can be created."""
        from securevibes_mcp.agents.dast_tester import TestPayload

        payload = TestPayload(
            value="' OR '1'='1",
            cwe_id="CWE-89",
            description="SQL injection test",
        )
        assert payload.value == "' OR '1'='1"
        assert payload.cwe_id == "CWE-89"


class TestDASTTester:
    """Tests for DASTTester class."""

    def test_tester_creation(self):
        """Test that DASTTester can be created."""
        from securevibes_mcp.agents.dast_tester import DASTTester

        tester = DASTTester(target_url="http://localhost:8080")
        assert tester is not None
        assert tester.target_url == "http://localhost:8080"

    def test_tester_accepts_https_url(self):
        """Test that DASTTester accepts HTTPS URLs."""
        from securevibes_mcp.agents.dast_tester import DASTTester

        tester = DASTTester(target_url="https://example.com")
        assert tester.target_url == "https://example.com"

    def test_tester_rejects_empty_url(self):
        """Test that DASTTester rejects empty URL."""
        from securevibes_mcp.agents.dast_tester import DASTTester, InvalidTargetURLError

        with pytest.raises(InvalidTargetURLError, match="cannot be empty"):
            DASTTester(target_url="")

    def test_tester_rejects_url_without_scheme(self):
        """Test that DASTTester rejects URL without proper scheme."""
        from securevibes_mcp.agents.dast_tester import DASTTester, InvalidTargetURLError

        # "localhost:8080" is parsed as scheme="localhost", so it fails scheme validation
        with pytest.raises(InvalidTargetURLError, match="http or https"):
            DASTTester(target_url="localhost:8080")

    def test_tester_rejects_non_http_scheme(self):
        """Test that DASTTester rejects non-HTTP schemes."""
        from securevibes_mcp.agents.dast_tester import DASTTester, InvalidTargetURLError

        with pytest.raises(InvalidTargetURLError, match="http or https"):
            DASTTester(target_url="ftp://example.com")

    def test_tester_rejects_url_without_host(self):
        """Test that DASTTester rejects URL without host."""
        from securevibes_mcp.agents.dast_tester import DASTTester, InvalidTargetURLError

        with pytest.raises(InvalidTargetURLError, match="missing host"):
            DASTTester(target_url="http://")

    @pytest.mark.asyncio
    async def test_tester_detects_sql_error(self):
        """Test that tester detects SQL errors in response."""
        from securevibes_mcp.agents.dast_tester import DASTTester

        tester = DASTTester(target_url="http://localhost:8080")

        # Mock response with SQL error
        mock_response = MagicMock()
        mock_response.text = "You have an error in your SQL syntax"
        mock_response.status_code = 500

        exploitable, evidence = tester._detect_sql_injection(mock_response)

        assert exploitable is True
        assert "SQL" in evidence

    @pytest.mark.asyncio
    async def test_tester_detects_xss_reflection(self):
        """Test that tester detects XSS reflection."""
        from securevibes_mcp.agents.dast_tester import DASTTester

        tester = DASTTester(target_url="http://localhost:8080")

        mock_response = MagicMock()
        mock_response.text = "Welcome <script>alert(1)</script> user"
        mock_response.status_code = 200

        exploitable, evidence = tester._detect_xss_reflection(
            mock_response, "<script>alert(1)</script>"
        )

        assert exploitable is True
        assert "reflected" in evidence.lower()

    @pytest.mark.asyncio
    async def test_tester_detects_path_traversal(self):
        """Test that tester detects path traversal."""
        from securevibes_mcp.agents.dast_tester import DASTTester

        tester = DASTTester(target_url="http://localhost:8080")

        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.status_code = 200

        exploitable, evidence = tester._detect_path_traversal(mock_response)

        assert exploitable is True
        assert "path traversal" in evidence.lower()

    @pytest.mark.asyncio
    async def test_test_vulnerability_with_mock(self):
        """Test the full test_vulnerability flow with mocked HTTP."""
        from securevibes_mcp.agents.dast_tester import DASTTester

        tester = DASTTester(target_url="http://localhost:8080")

        vulnerability = {
            "id": "VULN-001",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "file_path": "/app/db.py",
        }

        # Mock the HTTP client
        mock_response = MagicMock()
        mock_response.text = "You have an error in your SQL syntax"
        mock_response.status_code = 500
        mock_response.elapsed.total_seconds.return_value = 0.15

        with patch.object(tester, "_make_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await tester.test_vulnerability(vulnerability)

        assert result is not None
        assert result.vulnerability_id == "VULN-001"
        assert result.exploitable is True


class TestDetectionPatterns:
    """Tests for vulnerability detection patterns."""

    def test_detect_command_injection(self):
        """Test detecting command injection patterns."""
        from securevibes_mcp.agents.dast_tester import DASTTester

        tester = DASTTester(target_url="http://localhost:8080")

        mock_response = MagicMock()
        mock_response.text = "uid=0(root) gid=0(root)"
        mock_response.status_code = 200

        exploitable, evidence = tester._detect_command_injection(mock_response)

        assert exploitable is True

    def test_no_false_positive_on_clean_response(self):
        """Test that clean responses don't trigger false positives."""
        from securevibes_mcp.agents.dast_tester import DASTTester

        tester = DASTTester(target_url="http://localhost:8080")

        mock_response = MagicMock()
        mock_response.text = "Welcome to our application!"
        mock_response.status_code = 200

        sql_result = tester._detect_sql_injection(mock_response)
        assert sql_result[0] is False

        path_result = tester._detect_path_traversal(mock_response)
        assert path_result[0] is False
