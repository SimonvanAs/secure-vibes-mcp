"""Tests for query tool implementations."""

from pathlib import Path

import pytest


class TestGetScanStatusTool:
    """Tests for get_scan_status tool handler."""

    @pytest.mark.asyncio
    async def test_get_scan_status_returns_success(self, tmp_path: Path):
        """Test that get_scan_status returns success response."""
        from securevibes_mcp.tools.handlers import get_scan_status

        result = await get_scan_status(path=str(tmp_path))

        assert result["error"] is False
        assert "artifacts" in result

    @pytest.mark.asyncio
    async def test_get_scan_status_includes_all_artifacts(self, tmp_path: Path):
        """Test that response includes all artifact names."""
        from securevibes_mcp.tools.handlers import get_scan_status

        result = await get_scan_status(path=str(tmp_path))
        artifacts = result["artifacts"]

        expected = [
            "SECURITY.md",
            "THREAT_MODEL.json",
            "VULNERABILITIES.json",
            "DAST_VALIDATION.json",
            "scan_results.json",
        ]
        for name in expected:
            assert name in artifacts, f"Missing artifact: {name}"

    @pytest.mark.asyncio
    async def test_get_scan_status_no_artifacts(self, tmp_path: Path):
        """Test status when no artifacts exist."""
        from securevibes_mcp.tools.handlers import get_scan_status

        result = await get_scan_status(path=str(tmp_path))

        # All artifacts should show as not existing
        for _name, status in result["artifacts"].items():
            assert status["exists"] is False

    @pytest.mark.asyncio
    async def test_get_scan_status_with_existing_artifact(self, tmp_path: Path):
        """Test status when some artifacts exist."""
        from securevibes_mcp.storage import ScanStateManager
        from securevibes_mcp.tools.handlers import get_scan_status

        # Create an artifact
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", "# Security")

        result = await get_scan_status(path=str(tmp_path))

        assert result["artifacts"]["SECURITY.md"]["exists"] is True
        assert result["artifacts"]["SECURITY.md"]["size"] == 10
        assert result["artifacts"]["THREAT_MODEL.json"]["exists"] is False

    @pytest.mark.asyncio
    async def test_get_scan_status_includes_path(self, tmp_path: Path):
        """Test that response includes the scanned path."""
        from securevibes_mcp.tools.handlers import get_scan_status

        result = await get_scan_status(path=str(tmp_path))

        assert result["path"] == str(tmp_path)

    @pytest.mark.asyncio
    async def test_get_scan_status_artifact_metadata(self, tmp_path: Path):
        """Test that artifact status includes full metadata."""
        from securevibes_mcp.storage import ScanStateManager
        from securevibes_mcp.tools.handlers import get_scan_status

        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", "content")

        result = await get_scan_status(path=str(tmp_path))
        artifact = result["artifacts"]["SECURITY.md"]

        assert "exists" in artifact
        assert "size" in artifact
        assert "modified_at" in artifact


class TestGetArtifactTool:
    """Tests for get_artifact tool handler."""

    @pytest.mark.asyncio
    async def test_get_artifact_returns_content(self, tmp_path: Path):
        """Test that get_artifact returns artifact content."""
        from securevibes_mcp.storage import ScanStateManager
        from securevibes_mcp.tools.handlers import get_artifact

        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", "# Security Analysis")

        result = await get_artifact(
            path=str(tmp_path), artifact_name="SECURITY.md"
        )

        assert result["error"] is False
        assert result["content"] == "# Security Analysis"

    @pytest.mark.asyncio
    async def test_get_artifact_not_found(self, tmp_path: Path):
        """Test get_artifact when artifact doesn't exist."""
        from securevibes_mcp.tools.handlers import get_artifact

        result = await get_artifact(
            path=str(tmp_path), artifact_name="SECURITY.md"
        )

        assert result["error"] is True
        assert result["code"] == "ARTIFACT_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_get_artifact_invalid_name(self, tmp_path: Path):
        """Test get_artifact with invalid artifact name."""
        from securevibes_mcp.tools.handlers import get_artifact

        result = await get_artifact(
            path=str(tmp_path), artifact_name="INVALID.txt"
        )

        assert result["error"] is True
        assert result["code"] == "INVALID_ARTIFACT_NAME"

    @pytest.mark.asyncio
    async def test_get_artifact_includes_metadata(self, tmp_path: Path):
        """Test that get_artifact includes metadata."""
        from securevibes_mcp.storage import ScanStateManager
        from securevibes_mcp.tools.handlers import get_artifact

        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", "content")

        result = await get_artifact(
            path=str(tmp_path), artifact_name="SECURITY.md"
        )

        assert "artifact_name" in result
        assert result["artifact_name"] == "SECURITY.md"
        assert "size" in result
        assert "path" in result
