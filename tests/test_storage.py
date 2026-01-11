"""Tests for artifact storage layer."""

import json
import time
from pathlib import Path

import pytest


class TestScanStateManagerInit:
    """Tests for ScanStateManager initialization."""

    def test_import_scan_state_manager(self):
        """Test that ScanStateManager can be imported."""
        from securevibes_mcp.storage import ScanStateManager

        assert ScanStateManager is not None

    def test_create_scan_state_manager(self, tmp_path: Path):
        """Test that ScanStateManager can be created."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        assert manager.project_path == tmp_path

    def test_securevibes_dir_path(self, tmp_path: Path):
        """Test that .securevibes directory path is correct."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        assert manager.storage_dir == tmp_path / ".securevibes"


class TestDirectoryCreation:
    """Tests for directory creation."""

    def test_init_creates_securevibes_dir(self, tmp_path: Path):
        """Test that init() creates .securevibes directory."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        assert (tmp_path / ".securevibes").exists()
        assert (tmp_path / ".securevibes").is_dir()

    def test_init_is_idempotent(self, tmp_path: Path):
        """Test that init() can be called multiple times."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        manager.init()  # Should not raise
        assert (tmp_path / ".securevibes").exists()

    def test_init_preserves_existing_files(self, tmp_path: Path):
        """Test that init() does not delete existing files."""
        from securevibes_mcp.storage import ScanStateManager

        # Create directory and file manually
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        existing_file = securevibes_dir / "existing.txt"
        existing_file.write_text("existing content")

        manager = ScanStateManager(tmp_path)
        manager.init()

        assert existing_file.exists()
        assert existing_file.read_text() == "existing content"


class TestArtifactWriteOperations:
    """Tests for artifact write operations."""

    def test_write_artifact_creates_file(self, tmp_path: Path):
        """Test that write_artifact creates the artifact file."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        manager.write_artifact("SECURITY.md", "# Security Analysis")

        artifact_path = tmp_path / ".securevibes" / "SECURITY.md"
        assert artifact_path.exists()

    def test_write_artifact_content(self, tmp_path: Path):
        """Test that write_artifact writes correct content."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        content = "# Security Analysis\n\nThis is a test."
        manager.write_artifact("SECURITY.md", content)

        artifact_path = tmp_path / ".securevibes" / "SECURITY.md"
        assert artifact_path.read_text() == content

    def test_write_artifact_overwrites_existing(self, tmp_path: Path):
        """Test that write_artifact overwrites existing artifact."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        manager.write_artifact("SECURITY.md", "old content")
        manager.write_artifact("SECURITY.md", "new content")

        artifact_path = tmp_path / ".securevibes" / "SECURITY.md"
        assert artifact_path.read_text() == "new content"

    def test_write_json_artifact(self, tmp_path: Path):
        """Test that JSON artifacts are written correctly."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        data = {"threats": [{"id": "T1", "severity": "high"}]}
        manager.write_artifact("THREAT_MODEL.json", json.dumps(data, indent=2))

        artifact_path = tmp_path / ".securevibes" / "THREAT_MODEL.json"
        assert json.loads(artifact_path.read_text()) == data

    def test_write_artifact_auto_inits(self, tmp_path: Path):
        """Test that write_artifact creates directory if not exists."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        # Don't call init()
        manager.write_artifact("SECURITY.md", "content")

        assert (tmp_path / ".securevibes").exists()
        assert (tmp_path / ".securevibes" / "SECURITY.md").exists()


class TestArtifactReadOperations:
    """Tests for artifact read operations."""

    def test_read_artifact_returns_content(self, tmp_path: Path):
        """Test that read_artifact returns file content."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        content = "# Security Analysis"
        manager.write_artifact("SECURITY.md", content)

        result = manager.read_artifact("SECURITY.md")
        assert result == content

    def test_read_artifact_not_found_returns_none(self, tmp_path: Path):
        """Test that read_artifact returns None for missing artifact."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()

        result = manager.read_artifact("NONEXISTENT.md")
        assert result is None

    def test_read_artifact_no_init_returns_none(self, tmp_path: Path):
        """Test that read_artifact returns None when not initialized."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        # Don't call init()

        result = manager.read_artifact("SECURITY.md")
        assert result is None

    def test_artifact_exists_true(self, tmp_path: Path):
        """Test that artifact_exists returns True for existing artifact."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        manager.write_artifact("SECURITY.md", "content")

        assert manager.artifact_exists("SECURITY.md") is True

    def test_artifact_exists_false(self, tmp_path: Path):
        """Test that artifact_exists returns False for missing artifact."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()

        assert manager.artifact_exists("SECURITY.md") is False


class TestValidArtifactNames:
    """Tests for artifact name validation."""

    VALID_ARTIFACTS = [
        "SECURITY.md",
        "THREAT_MODEL.json",
        "VULNERABILITIES.json",
        "DAST_VALIDATION.json",
        "scan_results.json",
    ]

    @pytest.mark.parametrize("artifact_name", VALID_ARTIFACTS)
    def test_valid_artifact_names_accepted(self, tmp_path: Path, artifact_name: str):
        """Test that valid artifact names are accepted."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        # Should not raise
        manager.write_artifact(artifact_name, "content")
        assert manager.artifact_exists(artifact_name)

    def test_invalid_artifact_name_rejected(self, tmp_path: Path):
        """Test that invalid artifact names are rejected."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()

        with pytest.raises(ValueError, match="Invalid artifact name"):
            manager.write_artifact("INVALID.txt", "content")

    def test_path_traversal_rejected(self, tmp_path: Path):
        """Test that path traversal attempts are rejected."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()

        with pytest.raises(ValueError, match="Invalid artifact name"):
            manager.write_artifact("../etc/passwd", "malicious")

        with pytest.raises(ValueError, match="Invalid artifact name"):
            manager.write_artifact("/etc/passwd", "malicious")


class TestArtifactStatus:
    """Tests for artifact status checking."""

    def test_get_status_returns_dict(self, tmp_path: Path):
        """Test that get_status returns a dictionary."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()

        status = manager.get_status()
        assert isinstance(status, dict)

    def test_get_status_includes_all_artifacts(self, tmp_path: Path):
        """Test that get_status includes all valid artifact names."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()

        status = manager.get_status()
        expected_artifacts = [
            "SECURITY.md",
            "THREAT_MODEL.json",
            "VULNERABILITIES.json",
            "DAST_VALIDATION.json",
            "scan_results.json",
        ]
        for artifact in expected_artifacts:
            assert artifact in status, f"Missing artifact: {artifact}"

    def test_get_status_missing_artifact(self, tmp_path: Path):
        """Test status for missing artifact."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()

        status = manager.get_status()
        artifact_status = status["SECURITY.md"]

        assert artifact_status["exists"] is False
        assert artifact_status["size"] is None
        assert artifact_status["modified_at"] is None

    def test_get_status_existing_artifact(self, tmp_path: Path):
        """Test status for existing artifact."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        content = "# Security Analysis\n\nTest content here."
        manager.write_artifact("SECURITY.md", content)

        status = manager.get_status()
        artifact_status = status["SECURITY.md"]

        assert artifact_status["exists"] is True
        assert artifact_status["size"] == len(content)
        assert artifact_status["modified_at"] is not None
        assert isinstance(artifact_status["modified_at"], float)

    def test_get_status_multiple_artifacts(self, tmp_path: Path):
        """Test status with multiple artifacts present."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        manager.write_artifact("SECURITY.md", "security content")
        manager.write_artifact("THREAT_MODEL.json", '{"threats": []}')

        status = manager.get_status()

        assert status["SECURITY.md"]["exists"] is True
        assert status["THREAT_MODEL.json"]["exists"] is True
        assert status["VULNERABILITIES.json"]["exists"] is False

    def test_get_status_size_is_accurate(self, tmp_path: Path):
        """Test that reported size matches actual file size."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        manager.init()
        content = "A" * 1000  # 1000 bytes
        manager.write_artifact("SECURITY.md", content)

        status = manager.get_status()
        assert status["SECURITY.md"]["size"] == 1000

    def test_get_status_modified_at_is_recent(self, tmp_path: Path):
        """Test that modified_at timestamp is recent."""
        from securevibes_mcp.storage import ScanStateManager

        before = time.time()
        manager = ScanStateManager(tmp_path)
        manager.init()
        manager.write_artifact("SECURITY.md", "content")
        after = time.time()

        status = manager.get_status()
        modified_at = status["SECURITY.md"]["modified_at"]

        assert before <= modified_at <= after

    def test_get_status_no_init(self, tmp_path: Path):
        """Test get_status when directory not initialized."""
        from securevibes_mcp.storage import ScanStateManager

        manager = ScanStateManager(tmp_path)
        # Don't call init()

        status = manager.get_status()

        # All artifacts should show as non-existent
        for _artifact_name, artifact_status in status.items():
            assert artifact_status["exists"] is False
            assert artifact_status["size"] is None
            assert artifact_status["modified_at"] is None
