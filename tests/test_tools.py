"""Tests for MCP tool registration and dispatch."""

import pytest

from securevibes_mcp.server import SecureVibesMCPServer

# Expected tools based on spec
EXPECTED_TOOLS = [
    "run_assessment",
    "run_threat_modeling",
    "run_code_review",
    "run_dast",
    "generate_report",
    "get_scan_status",
    "get_artifact",
    "get_vulnerabilities",
    "suppress_vulnerability",
    "remove_suppression",
    "list_suppressions",
]


class TestToolRegistration:
    """Tests for tool registration."""

    def test_server_has_tools_registered(self):
        """Test that server has tools registered."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        assert len(tools) == 11

    def test_all_expected_tools_registered(self):
        """Test that all expected tools are registered."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        tool_names = [t.name for t in tools]
        for expected in EXPECTED_TOOLS:
            assert expected in tool_names, f"Tool {expected} not registered"

    def test_tools_have_descriptions(self):
        """Test that all tools have descriptions."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        for tool in tools:
            assert tool.description, f"Tool {tool.name} has no description"

    def test_tools_have_input_schemas(self):
        """Test that all tools have input schemas."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        for tool in tools:
            assert tool.inputSchema is not None, f"Tool {tool.name} has no input schema"


class TestToolSchemas:
    """Tests for tool input schemas."""

    def test_run_assessment_schema(self):
        """Test run_assessment has correct schema."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        tool = next(t for t in tools if t.name == "run_assessment")

        schema = tool.inputSchema
        assert "properties" in schema
        assert "path" in schema["properties"]
        assert schema["properties"]["path"]["type"] == "string"
        assert "path" in schema.get("required", [])

    def test_get_scan_status_schema(self):
        """Test get_scan_status has correct schema."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        tool = next(t for t in tools if t.name == "get_scan_status")

        schema = tool.inputSchema
        assert "properties" in schema
        assert "path" in schema["properties"]

    def test_get_artifact_schema(self):
        """Test get_artifact has correct schema."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        tool = next(t for t in tools if t.name == "get_artifact")

        schema = tool.inputSchema
        assert "properties" in schema
        assert "path" in schema["properties"]
        assert "artifact_name" in schema["properties"]


class TestToolDispatch:
    """Tests for tool dispatch mechanism."""

    @pytest.mark.asyncio
    async def test_call_tool_returns_result(self):
        """Test that calling a tool returns a result."""
        server = SecureVibesMCPServer()
        result = await server.call_tool("get_scan_status", {"path": "/tmp/test"})
        assert result is not None

    @pytest.mark.asyncio
    async def test_call_unknown_tool_raises_error(self):
        """Test that calling unknown tool raises error."""
        server = SecureVibesMCPServer()
        with pytest.raises(ValueError, match="Unknown tool"):
            await server.call_tool("unknown_tool", {})

    @pytest.mark.asyncio
    async def test_call_tool_validates_arguments(self):
        """Test that tool call validates required arguments."""
        server = SecureVibesMCPServer()
        # run_assessment requires path
        with pytest.raises((ValueError, TypeError)):
            await server.call_tool("run_assessment", {})


class TestGetVulnerabilities:
    """Tests for get_vulnerabilities tool."""

    @pytest.mark.asyncio
    async def test_get_vulnerabilities_no_artifact(self, tmp_path):
        """Test get_vulnerabilities when VULNERABILITIES.json doesn't exist."""
        server = SecureVibesMCPServer()
        result = await server.call_tool("get_vulnerabilities", {"path": str(tmp_path)})

        assert result["error"] is True
        assert result["code"] == "ARTIFACT_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_get_vulnerabilities_returns_data(self, tmp_path):
        """Test get_vulnerabilities returns vulnerability data."""
        import json

        # Create VULNERABILITIES.json artifact
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {"id": "VULN-001", "severity": "critical", "cwe_id": "CWE-89"},
                {"id": "VULN-002", "severity": "high", "cwe_id": "CWE-79"},
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        server = SecureVibesMCPServer()
        result = await server.call_tool("get_vulnerabilities", {"path": str(tmp_path)})

        assert result["error"] is False
        assert result["total_count"] == 2
        assert len(result["vulnerabilities"]) == 2

    @pytest.mark.asyncio
    async def test_get_vulnerabilities_filter_by_severity(self, tmp_path):
        """Test filtering vulnerabilities by severity."""
        import json

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {"id": "VULN-001", "severity": "critical"},
                {"id": "VULN-002", "severity": "high"},
                {"id": "VULN-003", "severity": "medium"},
                {"id": "VULN-004", "severity": "low"},
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "get_vulnerabilities", {"path": str(tmp_path), "severity": "high"}
        )

        assert result["error"] is False
        assert result["total_count"] == 2  # critical and high
        severities = [v["severity"] for v in result["vulnerabilities"]]
        assert "critical" in severities
        assert "high" in severities
        assert "medium" not in severities
        assert "low" not in severities

    @pytest.mark.asyncio
    async def test_get_vulnerabilities_filter_by_cwe(self, tmp_path):
        """Test filtering vulnerabilities by CWE ID."""
        import json

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {"id": "VULN-001", "severity": "critical", "cwe_id": "CWE-89"},
                {"id": "VULN-002", "severity": "high", "cwe_id": "CWE-79"},
                {"id": "VULN-003", "severity": "high", "cwe_id": "CWE-89"},
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "get_vulnerabilities", {"path": str(tmp_path), "cwe_id": "CWE-89"}
        )

        assert result["error"] is False
        assert result["total_count"] == 2
        for v in result["vulnerabilities"]:
            assert v["cwe_id"] == "CWE-89"

    @pytest.mark.asyncio
    async def test_get_vulnerabilities_filter_by_file_path(self, tmp_path):
        """Test filtering vulnerabilities by file path pattern."""
        import json

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {"id": "VULN-001", "severity": "high", "file_path": "/app/auth/login.py"},
                {"id": "VULN-002", "severity": "high", "file_path": "/app/api/users.py"},
                {"id": "VULN-003", "severity": "high", "file_path": "/app/auth/session.py"},
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "get_vulnerabilities", {"path": str(tmp_path), "file_path": "auth"}
        )

        assert result["error"] is False
        assert result["total_count"] == 2
        for v in result["vulnerabilities"]:
            assert "auth" in v["file_path"]

    @pytest.mark.asyncio
    async def test_get_vulnerabilities_respects_limit(self, tmp_path):
        """Test that limit parameter restricts results."""
        import json

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        vuln_data = {
            "version": "1.0.0",
            "vulnerabilities": [
                {"id": f"VULN-{i:03d}", "severity": "high"} for i in range(20)
            ],
        }
        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vuln_data))

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "get_vulnerabilities", {"path": str(tmp_path), "limit": 5}
        )

        assert result["error"] is False
        assert result["total_count"] == 20
        assert result["returned_count"] == 5
        assert len(result["vulnerabilities"]) == 5

    @pytest.mark.asyncio
    async def test_get_vulnerabilities_invalid_severity(self, tmp_path):
        """Test error on invalid severity value."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "VULNERABILITIES.json").write_text('{"vulnerabilities": []}')

        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "get_vulnerabilities", {"path": str(tmp_path), "severity": "invalid"}
        )

        assert result["error"] is True
        assert result["code"] == "INVALID_SEVERITY"
