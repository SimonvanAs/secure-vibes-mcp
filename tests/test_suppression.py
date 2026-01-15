"""Tests for suppression/baseline functionality."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from securevibes_mcp.agents.suppression_reader import Suppression, SuppressionReader
from securevibes_mcp.agents.suppression_writer import SuppressionWriter
from securevibes_mcp.server import SecureVibesMCPServer


class TestSuppression:
    """Tests for Suppression dataclass."""

    def test_suppression_from_dict(self):
        """Test creating Suppression from dict."""
        data = {
            "id": "SUPP-001",
            "type": "vuln_id",
            "vuln_id": "VULN-001",
            "reason": "false_positive",
            "justification": "Test justification",
            "suppressed_at": "2026-01-15T10:00:00Z",
        }
        suppression = Suppression.from_dict(data)

        assert suppression.id == "SUPP-001"
        assert suppression.type == "vuln_id"
        assert suppression.vuln_id == "VULN-001"
        assert suppression.reason == "false_positive"

    def test_suppression_to_dict(self):
        """Test converting Suppression to dict."""
        suppression = Suppression(
            id="SUPP-001",
            type="vuln_id",
            vuln_id="VULN-001",
            pattern=None,
            cwe_id=None,
            reason="false_positive",
            justification="Test",
            suppressed_at="2026-01-15T10:00:00Z",
        )
        data = suppression.to_dict()

        assert data["id"] == "SUPP-001"
        assert data["type"] == "vuln_id"
        assert data["vuln_id"] == "VULN-001"
        assert "pattern" not in data  # None values excluded
        assert "cwe_id" not in data

    def test_suppression_not_expired(self):
        """Test suppression without expiry is not expired."""
        suppression = Suppression(
            id="SUPP-001",
            type="vuln_id",
            vuln_id="VULN-001",
            pattern=None,
            cwe_id=None,
            reason="false_positive",
            justification="",
            suppressed_at="2026-01-15T10:00:00Z",
            expires_at=None,
        )
        assert not suppression.is_expired()

    def test_suppression_expired(self):
        """Test suppression with past expiry is expired."""
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        suppression = Suppression(
            id="SUPP-001",
            type="vuln_id",
            vuln_id="VULN-001",
            pattern=None,
            cwe_id=None,
            reason="false_positive",
            justification="",
            suppressed_at="2026-01-15T10:00:00Z",
            expires_at=past,
        )
        assert suppression.is_expired()

    def test_suppression_not_yet_expired(self):
        """Test suppression with future expiry is not expired."""
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        suppression = Suppression(
            id="SUPP-001",
            type="vuln_id",
            vuln_id="VULN-001",
            pattern=None,
            cwe_id=None,
            reason="false_positive",
            justification="",
            suppressed_at="2026-01-15T10:00:00Z",
            expires_at=future,
        )
        assert not suppression.is_expired()


class TestSuppressionReader:
    """Tests for SuppressionReader."""

    def test_reader_no_file(self, tmp_path):
        """Test reader when no SUPPRESSIONS.json exists."""
        reader = SuppressionReader(tmp_path)
        assert reader.read() is None
        assert reader.get_suppressions() == []
        assert reader.get_suppressed_vuln_ids() == set()

    def test_reader_empty_file(self, tmp_path):
        """Test reader with empty suppressions."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({"version": "1.0.0", "suppressions": []})
        )

        reader = SuppressionReader(tmp_path)
        assert reader.get_suppressions() == []

    def test_reader_vuln_id_match(self, tmp_path):
        """Test reader matches vuln_id suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "suppressions": [
                    {
                        "id": "SUPP-001",
                        "type": "vuln_id",
                        "vuln_id": "VULN-001",
                        "reason": "false_positive",
                        "justification": "",
                        "suppressed_at": "2026-01-15T10:00:00Z",
                    }
                ],
            })
        )

        reader = SuppressionReader(tmp_path)
        assert reader.is_suppressed({"id": "VULN-001"})
        assert not reader.is_suppressed({"id": "VULN-002"})

    def test_reader_file_pattern_match(self, tmp_path):
        """Test reader matches file_pattern suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "suppressions": [
                    {
                        "id": "SUPP-001",
                        "type": "file_pattern",
                        "pattern": "tests/",
                        "reason": "acceptable_risk",
                        "justification": "",
                        "suppressed_at": "2026-01-15T10:00:00Z",
                    }
                ],
            })
        )

        reader = SuppressionReader(tmp_path)
        assert reader.is_suppressed({"id": "VULN-001", "file_path": "/app/tests/test_foo.py"})
        assert not reader.is_suppressed({"id": "VULN-002", "file_path": "/app/src/foo.py"})

    def test_reader_cwe_pattern_match(self, tmp_path):
        """Test reader matches cwe_pattern suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "suppressions": [
                    {
                        "id": "SUPP-001",
                        "type": "cwe_pattern",
                        "cwe_id": "CWE-400",
                        "reason": "acceptable_risk",
                        "justification": "",
                        "suppressed_at": "2026-01-15T10:00:00Z",
                    }
                ],
            })
        )

        reader = SuppressionReader(tmp_path)
        assert reader.is_suppressed({"id": "VULN-001", "cwe_id": "CWE-400"})
        assert not reader.is_suppressed({"id": "VULN-002", "cwe_id": "CWE-89"})

    def test_reader_expired_ignored(self, tmp_path):
        """Test reader ignores expired suppressions by default."""
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "suppressions": [
                    {
                        "id": "SUPP-001",
                        "type": "vuln_id",
                        "vuln_id": "VULN-001",
                        "reason": "false_positive",
                        "justification": "",
                        "suppressed_at": "2026-01-15T10:00:00Z",
                        "expires_at": past,
                    }
                ],
            })
        )

        reader = SuppressionReader(tmp_path)
        assert not reader.is_suppressed({"id": "VULN-001"})
        assert len(reader.get_suppressions(include_expired=False)) == 0
        assert len(reader.get_suppressions(include_expired=True)) == 1


class TestSuppressionWriter:
    """Tests for SuppressionWriter."""

    def test_writer_add_vuln_id(self, tmp_path):
        """Test adding a vuln_id suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        writer = SuppressionWriter(tmp_path)
        suppression = writer.add(
            suppression_type="vuln_id",
            vuln_id="VULN-001",
            reason="false_positive",
            justification="Test justification",
        )

        assert suppression.id == "SUPP-001"
        assert suppression.type == "vuln_id"
        assert suppression.vuln_id == "VULN-001"

        # Verify file was created
        data = json.loads((securevibes_dir / "SUPPRESSIONS.json").read_text())
        assert len(data["suppressions"]) == 1

    def test_writer_add_increments_id(self, tmp_path):
        """Test adding multiple suppressions increments ID."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        writer = SuppressionWriter(tmp_path)
        s1 = writer.add(suppression_type="vuln_id", vuln_id="VULN-001", reason="false_positive")
        s2 = writer.add(suppression_type="vuln_id", vuln_id="VULN-002", reason="false_positive")
        s3 = writer.add(suppression_type="vuln_id", vuln_id="VULN-003", reason="false_positive")

        assert s1.id == "SUPP-001"
        assert s2.id == "SUPP-002"
        assert s3.id == "SUPP-003"

    def test_writer_add_file_pattern(self, tmp_path):
        """Test adding a file_pattern suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        writer = SuppressionWriter(tmp_path)
        suppression = writer.add(
            suppression_type="file_pattern",
            pattern="tests/",
            reason="acceptable_risk",
        )

        assert suppression.type == "file_pattern"
        assert suppression.pattern == "tests/"

    def test_writer_add_cwe_pattern(self, tmp_path):
        """Test adding a cwe_pattern suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        writer = SuppressionWriter(tmp_path)
        suppression = writer.add(
            suppression_type="cwe_pattern",
            cwe_id="CWE-400",
            reason="acceptable_risk",
        )

        assert suppression.type == "cwe_pattern"
        assert suppression.cwe_id == "CWE-400"

    def test_writer_add_invalid_type(self, tmp_path):
        """Test adding with invalid type raises error."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        writer = SuppressionWriter(tmp_path)
        with pytest.raises(ValueError, match="Invalid suppression type"):
            writer.add(suppression_type="invalid", reason="false_positive")

    def test_writer_add_invalid_reason(self, tmp_path):
        """Test adding with invalid reason raises error."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        writer = SuppressionWriter(tmp_path)
        with pytest.raises(ValueError, match="Invalid reason"):
            writer.add(
                suppression_type="vuln_id",
                vuln_id="VULN-001",
                reason="invalid_reason",
            )

    def test_writer_remove(self, tmp_path):
        """Test removing a suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        writer = SuppressionWriter(tmp_path)
        writer.add(suppression_type="vuln_id", vuln_id="VULN-001", reason="false_positive")
        writer.add(suppression_type="vuln_id", vuln_id="VULN-002", reason="false_positive")

        assert writer.remove("SUPP-001")

        reader = SuppressionReader(tmp_path)
        suppressions = reader.get_suppressions()
        assert len(suppressions) == 1
        assert suppressions[0].id == "SUPP-002"

    def test_writer_remove_not_found(self, tmp_path):
        """Test removing non-existent suppression returns False."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        writer = SuppressionWriter(tmp_path)
        assert not writer.remove("SUPP-999")


class TestGetVulnerabilitiesWithSuppression:
    """Tests for get_vulnerabilities with suppression filtering."""

    @pytest.mark.asyncio
    async def test_excludes_suppressed_by_default(self, tmp_path):
        """Test get_vulnerabilities excludes suppressed by default."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        # Create vulnerabilities
        (securevibes_dir / "VULNERABILITIES.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "vulnerabilities": [
                    {"id": "VULN-001", "severity": "high", "cwe_id": "CWE-89"},
                    {"id": "VULN-002", "severity": "high", "cwe_id": "CWE-79"},
                ],
            })
        )

        # Create suppression for VULN-001
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "suppressions": [
                    {
                        "id": "SUPP-001",
                        "type": "vuln_id",
                        "vuln_id": "VULN-001",
                        "reason": "false_positive",
                        "justification": "",
                        "suppressed_at": "2026-01-15T10:00:00Z",
                    }
                ],
            })
        )

        server = SecureVibesMCPServer()
        result = await server.call_tool("get_vulnerabilities", {"path": str(tmp_path)})

        assert result["error"] is False
        assert result["total_count"] == 1
        assert result["suppressed_count"] == 1
        assert result["vulnerabilities"][0]["id"] == "VULN-002"

    @pytest.mark.asyncio
    async def test_includes_suppressed_when_requested(self, tmp_path):
        """Test get_vulnerabilities includes suppressed when include_suppressed=True."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        # Create vulnerabilities
        (securevibes_dir / "VULNERABILITIES.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "vulnerabilities": [
                    {"id": "VULN-001", "severity": "high"},
                    {"id": "VULN-002", "severity": "high"},
                ],
            })
        )

        # Create suppression
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "suppressions": [
                    {
                        "id": "SUPP-001",
                        "type": "vuln_id",
                        "vuln_id": "VULN-001",
                        "reason": "false_positive",
                        "justification": "",
                        "suppressed_at": "2026-01-15T10:00:00Z",
                    }
                ],
            })
        )

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "get_vulnerabilities",
            {"path": str(tmp_path), "include_suppressed": True},
        )

        assert result["error"] is False
        assert result["total_count"] == 2
        assert result["suppressed_count"] == 0  # Not counted when included


class TestSuppressionTools:
    """Tests for suppression MCP tools."""

    @pytest.mark.asyncio
    async def test_suppress_vulnerability_tool(self, tmp_path):
        """Test suppress_vulnerability tool creates suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "suppress_vulnerability",
            {
                "path": str(tmp_path),
                "vuln_id": "VULN-001",
                "reason": "false_positive",
                "justification": "Test suppression",
            },
        )

        assert result["error"] is False
        assert result["suppression"]["id"] == "SUPP-001"
        assert result["suppression"]["vuln_id"] == "VULN-001"

    @pytest.mark.asyncio
    async def test_suppress_vulnerability_missing_target(self, tmp_path):
        """Test suppress_vulnerability requires a target."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "suppress_vulnerability",
            {"path": str(tmp_path), "reason": "false_positive"},
        )

        assert result["error"] is True
        assert result["code"] == "MISSING_TARGET"

    @pytest.mark.asyncio
    async def test_list_suppressions_tool(self, tmp_path):
        """Test list_suppressions tool returns suppressions."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "suppressions": [
                    {
                        "id": "SUPP-001",
                        "type": "vuln_id",
                        "vuln_id": "VULN-001",
                        "reason": "false_positive",
                        "justification": "",
                        "suppressed_at": "2026-01-15T10:00:00Z",
                    }
                ],
            })
        )

        server = SecureVibesMCPServer()
        result = await server.call_tool("list_suppressions", {"path": str(tmp_path)})

        assert result["error"] is False
        assert result["total_count"] == 1
        assert result["suppressions"][0]["id"] == "SUPP-001"

    @pytest.mark.asyncio
    async def test_remove_suppression_tool(self, tmp_path):
        """Test remove_suppression tool removes suppression."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SUPPRESSIONS.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "suppressions": [
                    {
                        "id": "SUPP-001",
                        "type": "vuln_id",
                        "vuln_id": "VULN-001",
                        "reason": "false_positive",
                        "justification": "",
                        "suppressed_at": "2026-01-15T10:00:00Z",
                    }
                ],
            })
        )

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "remove_suppression",
            {"path": str(tmp_path), "suppression_id": "SUPP-001"},
        )

        assert result["error"] is False
        assert "Removed" in result["message"]

        # Verify removed
        list_result = await server.call_tool("list_suppressions", {"path": str(tmp_path)})
        assert list_result["total_count"] == 0

    @pytest.mark.asyncio
    async def test_remove_suppression_not_found(self, tmp_path):
        """Test remove_suppression returns error for non-existent ID."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "remove_suppression",
            {"path": str(tmp_path), "suppression_id": "SUPP-999"},
        )

        assert result["error"] is True
        assert result["code"] == "NOT_FOUND"


class TestToolRegistration:
    """Tests for tool registration."""

    def test_suppression_tools_registered(self):
        """Test that all suppression tools are registered."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        tool_names = [t.name for t in tools]

        assert "suppress_vulnerability" in tool_names
        assert "remove_suppression" in tool_names
        assert "list_suppressions" in tool_names

    def test_total_tool_count(self):
        """Test total number of registered tools."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        assert len(tools) == 11  # 8 original + 3 suppression tools
