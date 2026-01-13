"""Tests for artifact readers."""

import json
from pathlib import Path

import pytest


class TestSecurityDocReader:
    """Tests for SecurityDocReader class."""

    def test_reader_creation(self, tmp_path: Path):
        """Test that SecurityDocReader can be created."""
        from securevibes_mcp.agents.artifact_readers import SecurityDocReader

        reader = SecurityDocReader(root_path=tmp_path)
        assert reader is not None

    def test_reader_returns_none_when_missing(self, tmp_path: Path):
        """Test that reader returns None when artifact is missing."""
        from securevibes_mcp.agents.artifact_readers import SecurityDocReader

        reader = SecurityDocReader(root_path=tmp_path)
        content = reader.read()
        assert content is None

    def test_reader_reads_security_doc(self, tmp_path: Path):
        """Test that reader reads SECURITY.md content."""
        from securevibes_mcp.agents.artifact_readers import SecurityDocReader

        # Create artifact
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        security_content = """# Security Overview

## Architecture
- Python backend
- React frontend

## Components
- Auth service
- API gateway
"""
        (securevibes_dir / "SECURITY.md").write_text(security_content)

        reader = SecurityDocReader(root_path=tmp_path)
        content = reader.read()

        assert content is not None
        assert "Security Overview" in content
        assert "Python backend" in content

    def test_reader_exists_returns_true_when_present(self, tmp_path: Path):
        """Test that exists() returns True when artifact is present."""
        from securevibes_mcp.agents.artifact_readers import SecurityDocReader

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SECURITY.md").write_text("# Security")

        reader = SecurityDocReader(root_path=tmp_path)
        assert reader.exists() is True

    def test_reader_exists_returns_false_when_missing(self, tmp_path: Path):
        """Test that exists() returns False when artifact is missing."""
        from securevibes_mcp.agents.artifact_readers import SecurityDocReader

        reader = SecurityDocReader(root_path=tmp_path)
        assert reader.exists() is False


class TestDASTValidationReader:
    """Tests for DASTValidationReader class."""

    def test_reader_creation(self, tmp_path: Path):
        """Test that DASTValidationReader can be created."""
        from securevibes_mcp.agents.artifact_readers import DASTValidationReader

        reader = DASTValidationReader(root_path=tmp_path)
        assert reader is not None

    def test_reader_returns_none_when_missing(self, tmp_path: Path):
        """Test that reader returns None when artifact is missing."""
        from securevibes_mcp.agents.artifact_readers import DASTValidationReader

        reader = DASTValidationReader(root_path=tmp_path)
        data = reader.read()
        assert data is None

    def test_reader_parses_valid_artifact(self, tmp_path: Path):
        """Test that reader parses valid DAST_VALIDATION.json."""
        from securevibes_mcp.agents.artifact_readers import DASTValidationReader

        # Create artifact
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        dast_data = {
            "version": "1.0.0",
            "generated_at": "2026-01-13T12:00:00Z",
            "target_url": "http://localhost:8080",
            "validations": [
                {
                    "vulnerability_id": "VULN-001",
                    "exploitable": True,
                    "evidence": "SQL error detected",
                    "http_status": 500,
                }
            ],
            "summary": {
                "total_tested": 1,
                "exploitable": 1,
                "not_exploitable": 0,
            },
        }
        (securevibes_dir / "DAST_VALIDATION.json").write_text(json.dumps(dast_data))

        reader = DASTValidationReader(root_path=tmp_path)
        data = reader.read()

        assert data is not None
        assert data["version"] == "1.0.0"
        assert data["target_url"] == "http://localhost:8080"
        assert len(data["validations"]) == 1

    def test_reader_get_exploitable(self, tmp_path: Path):
        """Test getting exploitable vulnerabilities."""
        from securevibes_mcp.agents.artifact_readers import DASTValidationReader

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        dast_data = {
            "version": "1.0.0",
            "validations": [
                {"vulnerability_id": "VULN-001", "exploitable": True},
                {"vulnerability_id": "VULN-002", "exploitable": False},
                {"vulnerability_id": "VULN-003", "exploitable": True},
            ],
        }
        (securevibes_dir / "DAST_VALIDATION.json").write_text(json.dumps(dast_data))

        reader = DASTValidationReader(root_path=tmp_path)
        exploitable = reader.get_exploitable()

        assert len(exploitable) == 2
        assert exploitable[0]["vulnerability_id"] == "VULN-001"
        assert exploitable[1]["vulnerability_id"] == "VULN-003"

    def test_reader_get_exploitable_ids(self, tmp_path: Path):
        """Test getting exploitable vulnerability IDs."""
        from securevibes_mcp.agents.artifact_readers import DASTValidationReader

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        dast_data = {
            "version": "1.0.0",
            "validations": [
                {"vulnerability_id": "VULN-001", "exploitable": True},
                {"vulnerability_id": "VULN-002", "exploitable": False},
                {"vulnerability_id": "VULN-003", "exploitable": True},
            ],
        }
        (securevibes_dir / "DAST_VALIDATION.json").write_text(json.dumps(dast_data))

        reader = DASTValidationReader(root_path=tmp_path)
        ids = reader.get_exploitable_ids()

        assert ids == {"VULN-001", "VULN-003"}

    def test_reader_exists_returns_true_when_present(self, tmp_path: Path):
        """Test that exists() returns True when artifact is present."""
        from securevibes_mcp.agents.artifact_readers import DASTValidationReader

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "DAST_VALIDATION.json").write_text('{"version": "1.0.0"}')

        reader = DASTValidationReader(root_path=tmp_path)
        assert reader.exists() is True

    def test_reader_exists_returns_false_when_missing(self, tmp_path: Path):
        """Test that exists() returns False when artifact is missing."""
        from securevibes_mcp.agents.artifact_readers import DASTValidationReader

        reader = DASTValidationReader(root_path=tmp_path)
        assert reader.exists() is False

    def test_reader_returns_empty_on_invalid_json(self, tmp_path: Path):
        """Test that reader handles invalid JSON gracefully."""
        from securevibes_mcp.agents.artifact_readers import DASTValidationReader

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "DAST_VALIDATION.json").write_text("not valid json")

        reader = DASTValidationReader(root_path=tmp_path)
        data = reader.read()

        assert data is None
