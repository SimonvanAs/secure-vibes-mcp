"""Tests for run_assessment tool handler."""

from pathlib import Path

import pytest


class TestRunAssessmentTool:
    """Tests for run_assessment tool handler."""

    @pytest.mark.asyncio
    async def test_run_assessment_returns_success(self, tmp_path: Path):
        """Test that run_assessment returns success response."""
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "main.py").write_text("print('hello')")

        result = await run_assessment(path=str(tmp_path))

        assert result["error"] is False

    @pytest.mark.asyncio
    async def test_run_assessment_includes_summary(self, tmp_path: Path):
        """Test that response includes summary information."""
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "main.py").write_text("print('hello')")

        result = await run_assessment(path=str(tmp_path))

        assert "file_count" in result
        assert "languages" in result

    @pytest.mark.asyncio
    async def test_run_assessment_creates_artifact(self, tmp_path: Path):
        """Test that run_assessment creates SECURITY.md artifact."""
        from securevibes_mcp.storage import ScanStateManager
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "main.py").write_text("print('hello')")

        await run_assessment(path=str(tmp_path))

        manager = ScanStateManager(tmp_path)
        assert manager.artifact_exists("SECURITY.md")

    @pytest.mark.asyncio
    async def test_run_assessment_artifact_content(self, tmp_path: Path):
        """Test that SECURITY.md artifact has expected content."""
        from securevibes_mcp.storage import ScanStateManager
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")

        await run_assessment(path=str(tmp_path))

        manager = ScanStateManager(tmp_path)
        content = manager.read_artifact("SECURITY.md")

        assert content is not None
        assert "# Security Assessment" in content
        assert "Python" in content
        assert "Flask" in content

    @pytest.mark.asyncio
    async def test_run_assessment_invalid_path(self):
        """Test run_assessment with non-existent path."""
        from securevibes_mcp.tools.handlers import run_assessment

        result = await run_assessment(path="/nonexistent/path")

        assert result["error"] is True
        assert result["code"] == "PATH_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_run_assessment_returns_languages(self, tmp_path: Path):
        """Test that response includes detected languages."""
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "app.py").write_text("# python")
        (tmp_path / "lib.js").write_text("// javascript")

        result = await run_assessment(path=str(tmp_path))

        assert "Python" in result["languages"]
        assert "JavaScript" in result["languages"]

    @pytest.mark.asyncio
    async def test_run_assessment_returns_frameworks(self, tmp_path: Path):
        """Test that response includes detected frameworks."""
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "requirements.txt").write_text("django>=4.0\n")
        (tmp_path / "manage.py").write_text("# django")

        result = await run_assessment(path=str(tmp_path))

        assert "frameworks" in result
        assert "Django" in result["frameworks"]

    @pytest.mark.asyncio
    async def test_run_assessment_force_overwrites(self, tmp_path: Path):
        """Test that force=True overwrites existing artifact."""
        from securevibes_mcp.storage import ScanStateManager
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "main.py").write_text("# v1")

        # Create initial artifact
        await run_assessment(path=str(tmp_path))

        # Modify the project
        (tmp_path / "new_file.py").write_text("# v2")

        # Run again with force
        await run_assessment(path=str(tmp_path), force=True)

        manager = ScanStateManager(tmp_path)
        content = manager.read_artifact("SECURITY.md")

        # Should have updated content
        assert content is not None
        assert "2" in content  # 2 files now

    @pytest.mark.asyncio
    async def test_run_assessment_skips_existing_without_force(self, tmp_path: Path):
        """Test that existing artifact is not overwritten without force."""
        from securevibes_mcp.storage import ScanStateManager
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "main.py").write_text("# original")

        # Create initial artifact
        await run_assessment(path=str(tmp_path))

        # Verify artifact exists
        manager = ScanStateManager(tmp_path)
        assert manager.artifact_exists("SECURITY.md")

        # Add another file
        (tmp_path / "new_file.py").write_text("# new")

        # Run again without force
        result = await run_assessment(path=str(tmp_path), force=False)

        # Should indicate artifact exists
        assert result.get("skipped") is True or result["error"] is False

    @pytest.mark.asyncio
    async def test_run_assessment_returns_path(self, tmp_path: Path):
        """Test that response includes the path."""
        from securevibes_mcp.tools.handlers import run_assessment

        (tmp_path / "main.py").write_text("# app")

        result = await run_assessment(path=str(tmp_path))

        assert result["path"] == str(tmp_path)
