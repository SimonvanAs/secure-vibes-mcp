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
]


class TestToolRegistration:
    """Tests for tool registration."""

    def test_server_has_tools_registered(self):
        """Test that server has tools registered."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        assert len(tools) == 8

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


class TestPlaceholderResponses:
    """Tests for placeholder tool implementations."""

    @pytest.mark.asyncio
    async def test_placeholder_returns_not_implemented_error(self):
        """Test that placeholder tools return not implemented error."""
        server = SecureVibesMCPServer()
        result = await server.call_tool("run_assessment", {"path": "/tmp/test"})

        assert result["error"] is True
        assert result["code"] == "NOT_IMPLEMENTED"

    @pytest.mark.asyncio
    async def test_placeholder_includes_tool_name(self):
        """Test that placeholder response includes the tool name."""
        server = SecureVibesMCPServer()
        result = await server.call_tool("run_assessment", {"path": "/tmp/test"})

        assert result["tool"] == "run_assessment"
        assert "run_assessment" in result["message"]

    @pytest.mark.asyncio
    async def test_all_agent_tools_return_placeholder(self):
        """Test that all agent tools return placeholder responses."""
        server = SecureVibesMCPServer()
        agent_tools = [
            ("run_assessment", {"path": "/tmp"}),
            ("run_threat_modeling", {"path": "/tmp"}),
            ("run_code_review", {"path": "/tmp"}),
            ("run_dast", {"path": "/tmp", "target_url": "http://localhost"}),
            ("generate_report", {"path": "/tmp"}),
        ]

        for tool_name, args in agent_tools:
            result = await server.call_tool(tool_name, args)
            assert result["error"] is True, f"{tool_name} should return error"
            assert result["code"] == "NOT_IMPLEMENTED"
            assert result["tool"] == tool_name

    @pytest.mark.asyncio
    async def test_all_query_tools_return_placeholder(self):
        """Test that all query tools return placeholder responses."""
        server = SecureVibesMCPServer()
        query_tools = [
            ("get_scan_status", {"path": "/tmp"}),
            ("get_artifact", {"path": "/tmp", "artifact_name": "SECURITY.md"}),
            ("get_vulnerabilities", {"path": "/tmp"}),
        ]

        for tool_name, args in query_tools:
            result = await server.call_tool(tool_name, args)
            assert result["error"] is True, f"{tool_name} should return error"
            assert result["code"] == "NOT_IMPLEMENTED"
            assert result["tool"] == tool_name

    @pytest.mark.asyncio
    async def test_placeholder_response_structure(self):
        """Test that placeholder response has required fields."""
        server = SecureVibesMCPServer()
        result = await server.call_tool("get_scan_status", {"path": "/tmp"})

        # Verify all required fields are present
        assert "error" in result
        assert "code" in result
        assert "message" in result
        assert "tool" in result

        # Verify types
        assert isinstance(result["error"], bool)
        assert isinstance(result["code"], str)
        assert isinstance(result["message"], str)
        assert isinstance(result["tool"], str)
