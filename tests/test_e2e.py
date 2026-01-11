"""End-to-end integration tests for SecureVibes MCP Server."""

from pathlib import Path

import pytest

from securevibes_mcp.server import SecureVibesMCPServer


class TestAssessmentWorkflowE2E:
    """End-to-end tests for the complete assessment workflow."""

    @pytest.mark.asyncio
    async def test_complete_assessment_workflow(self, tmp_path: Path):
        """Test the full assessment workflow through the server."""
        # Setup: Create a realistic project structure
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n"
        )
        (tmp_path / "src" / "models.py").write_text(
            "class User:\n    pass\n"
        )
        (tmp_path / "requirements.txt").write_text("flask>=2.0.0\nsqlalchemy>=1.4\n")
        (tmp_path / "README.md").write_text("# Test Project\n")

        # Step 1: Run assessment via server
        server = SecureVibesMCPServer()
        result = await server.call_tool("run_assessment", {"path": str(tmp_path)})

        # Verify assessment succeeded
        assert result["error"] is False
        assert result["file_count"] >= 2
        assert "Python" in result["languages"]
        assert "Flask" in result["frameworks"]
        assert result["artifact"] == "SECURITY.md"

        # Step 2: Verify artifact via get_scan_status
        status = await server.call_tool("get_scan_status", {"path": str(tmp_path)})
        assert status["error"] is False
        assert status["artifacts"]["SECURITY.md"]["exists"] is True

        # Step 3: Retrieve artifact content
        artifact = await server.call_tool(
            "get_artifact",
            {"path": str(tmp_path), "artifact_name": "SECURITY.md"},
        )
        assert artifact["error"] is False
        assert "# Security Assessment" in artifact["content"]
        assert "Flask" in artifact["content"]

    @pytest.mark.asyncio
    async def test_assessment_with_multiple_languages(self, tmp_path: Path):
        """Test assessment with a multi-language project."""
        # Create files for multiple languages
        (tmp_path / "backend.py").write_text("# Python backend\n")
        (tmp_path / "frontend.js").write_text("// JavaScript frontend\n")
        (tmp_path / "styles.css").write_text("/* CSS styles */\n")
        (tmp_path / "package.json").write_text('{"name": "test", "dependencies": {"react": "^18.0.0"}}\n')

        server = SecureVibesMCPServer()
        result = await server.call_tool("run_assessment", {"path": str(tmp_path)})

        assert result["error"] is False
        assert "Python" in result["languages"]
        assert "JavaScript" in result["languages"]
        assert "React" in result["frameworks"]

    @pytest.mark.asyncio
    async def test_assessment_idempotency(self, tmp_path: Path):
        """Test that assessment is idempotent without force flag."""
        (tmp_path / "app.py").write_text("# app\n")

        server = SecureVibesMCPServer()

        # First assessment
        result1 = await server.call_tool("run_assessment", {"path": str(tmp_path)})
        assert result1["error"] is False
        assert "skipped" not in result1

        # Second assessment without force - should be skipped
        result2 = await server.call_tool("run_assessment", {"path": str(tmp_path)})
        assert result2["error"] is False
        assert result2.get("skipped") is True

        # Third assessment with force - should run again
        result3 = await server.call_tool(
            "run_assessment", {"path": str(tmp_path), "force": True}
        )
        assert result3["error"] is False
        assert "skipped" not in result3


class TestMCPProtocolIntegration:
    """Tests for MCP protocol integration."""

    def test_tool_registration_complete(self):
        """Test that all expected tools are registered."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_assessment",
            "run_threat_modeling",
            "run_code_review",
            "run_dast",
            "generate_report",
            "get_scan_status",
            "get_artifact",
            "get_vulnerabilities",
        }
        assert tool_names == expected

    def test_tools_have_valid_schemas(self):
        """Test that all tools have valid JSON schemas."""
        server = SecureVibesMCPServer()
        tools = server.list_tools()

        for tool in tools:
            schema = tool.inputSchema
            assert "type" in schema
            assert schema["type"] == "object"
            assert "properties" in schema

    @pytest.mark.asyncio
    async def test_tool_invocation_returns_structured_response(self):
        """Test that tool invocations return structured responses."""
        server = SecureVibesMCPServer()

        # Implemented tool returns success structure
        result = await server.call_tool("get_scan_status", {"path": "/tmp"})
        assert "error" in result

        # Unimplemented tool returns placeholder structure
        result = await server.call_tool("run_threat_modeling", {"path": "/tmp"})
        assert "error" in result
        assert "code" in result
        assert "message" in result


class TestArtifactPersistence:
    """Tests for artifact persistence across tool calls."""

    @pytest.mark.asyncio
    async def test_artifact_persists_across_server_instances(self, tmp_path: Path):
        """Test that artifacts persist when using different server instances."""
        (tmp_path / "main.py").write_text("# main\n")

        # Create artifact with first server instance
        server1 = SecureVibesMCPServer()
        await server1.call_tool("run_assessment", {"path": str(tmp_path)})

        # Verify artifact with second server instance
        server2 = SecureVibesMCPServer()
        status = await server2.call_tool("get_scan_status", {"path": str(tmp_path)})
        assert status["artifacts"]["SECURITY.md"]["exists"] is True

        # Retrieve content with third server instance
        server3 = SecureVibesMCPServer()
        artifact = await server3.call_tool(
            "get_artifact",
            {"path": str(tmp_path), "artifact_name": "SECURITY.md"},
        )
        assert artifact["error"] is False
        assert len(artifact["content"]) > 0

    @pytest.mark.asyncio
    async def test_artifact_isolation_between_projects(self, tmp_path: Path):
        """Test that artifacts are isolated between different projects."""
        # Create two separate projects
        project1 = tmp_path / "project1"
        project2 = tmp_path / "project2"
        project1.mkdir()
        project2.mkdir()

        (project1 / "app.py").write_text("# project 1\n")
        (project2 / "app.py").write_text("# project 2\n")

        server = SecureVibesMCPServer()

        # Run assessment on project1 only
        await server.call_tool("run_assessment", {"path": str(project1)})

        # Project1 should have artifact
        status1 = await server.call_tool("get_scan_status", {"path": str(project1)})
        assert status1["artifacts"]["SECURITY.md"]["exists"] is True

        # Project2 should NOT have artifact
        status2 = await server.call_tool("get_scan_status", {"path": str(project2)})
        assert status2["artifacts"]["SECURITY.md"]["exists"] is False

    @pytest.mark.asyncio
    async def test_multiple_artifacts_independent(self, tmp_path: Path):
        """Test that different artifact types are stored independently."""
        (tmp_path / "app.py").write_text("# app\n")

        server = SecureVibesMCPServer()

        # Run assessment (creates SECURITY.md)
        await server.call_tool("run_assessment", {"path": str(tmp_path)})

        # Check status - SECURITY.md exists, others don't
        status = await server.call_tool("get_scan_status", {"path": str(tmp_path)})
        assert status["artifacts"]["SECURITY.md"]["exists"] is True
        assert status["artifacts"]["THREAT_MODEL.json"]["exists"] is False
        assert status["artifacts"]["VULNERABILITIES.json"]["exists"] is False


class TestErrorHandling:
    """End-to-end tests for error handling."""

    @pytest.mark.asyncio
    async def test_invalid_path_error(self):
        """Test that invalid paths return proper errors."""
        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "run_assessment", {"path": "/nonexistent/path/12345"}
        )
        assert result["error"] is True
        assert result["code"] == "PATH_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_invalid_artifact_name_error(self, tmp_path: Path):
        """Test that invalid artifact names return proper errors."""
        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "get_artifact",
            {"path": str(tmp_path), "artifact_name": "INVALID.txt"},
        )
        assert result["error"] is True
        assert result["code"] == "INVALID_ARTIFACT_NAME"

    @pytest.mark.asyncio
    async def test_missing_artifact_error(self, tmp_path: Path):
        """Test that missing artifacts return proper errors."""
        server = SecureVibesMCPServer()
        result = await server.call_tool(
            "get_artifact",
            {"path": str(tmp_path), "artifact_name": "SECURITY.md"},
        )
        assert result["error"] is True
        assert result["code"] == "ARTIFACT_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_unknown_tool_error(self):
        """Test that unknown tools raise ValueError."""
        server = SecureVibesMCPServer()
        with pytest.raises(ValueError, match="Unknown tool"):
            await server.call_tool("nonexistent_tool", {})
