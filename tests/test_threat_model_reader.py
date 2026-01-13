"""Tests for THREAT_MODEL.json reader."""

import json
from pathlib import Path


class TestThreatModelReader:
    """Tests for ThreatModelReader class."""

    def test_reader_creation(self, tmp_path: Path):
        """Test that ThreatModelReader can be created."""
        from securevibes_mcp.agents.threat_model_reader import ThreatModelReader

        reader = ThreatModelReader(root_path=tmp_path)
        assert reader is not None

    def test_read_artifact_not_found(self, tmp_path: Path):
        """Test reading when THREAT_MODEL.json doesn't exist."""
        from securevibes_mcp.agents.threat_model_reader import ThreatModelReader

        reader = ThreatModelReader(root_path=tmp_path)
        result = reader.read()

        assert result is None

    def test_read_artifact_exists(self, tmp_path: Path):
        """Test reading when THREAT_MODEL.json exists."""
        from securevibes_mcp.agents.threat_model_reader import ThreatModelReader

        # Create .securevibes directory and THREAT_MODEL.json
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0",
            "generated_at": "2026-01-13T00:00:00Z",
            "project_path": str(tmp_path),
            "threats": [],
            "summary": {"total": 0},
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        reader = ThreatModelReader(root_path=tmp_path)
        result = reader.read()

        assert result is not None
        assert result["version"] == "1.0"

    def test_read_parses_threats(self, tmp_path: Path):
        """Test reading parses threat entries correctly."""
        from securevibes_mcp.agents.threat_model_reader import ThreatModelReader

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0",
            "generated_at": "2026-01-13T00:00:00Z",
            "project_path": str(tmp_path),
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "Spoofing",
                    "component": "API Gateway",
                    "description": "Test threat",
                    "attack_vector": "Stolen credentials",
                    "impact": "Unauthorized access",
                    "severity": "high",
                    "cvss_range": {"min": 7.0, "max": 8.9},
                }
            ],
            "summary": {"total": 1, "high": 1},
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        reader = ThreatModelReader(root_path=tmp_path)
        result = reader.read()

        assert result is not None
        assert len(result["threats"]) == 1
        assert result["threats"][0]["id"] == "THREAT-001"

    def test_read_invalid_json(self, tmp_path: Path):
        """Test reading invalid JSON returns None."""
        from securevibes_mcp.agents.threat_model_reader import ThreatModelReader

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "THREAT_MODEL.json").write_text("not valid json {")

        reader = ThreatModelReader(root_path=tmp_path)
        result = reader.read()

        assert result is None


class TestParsedThreatEntry:
    """Tests for ParsedThreatEntry dataclass."""

    def test_dataclass_creation(self):
        """Test ParsedThreatEntry can be created."""
        from securevibes_mcp.agents.threat_model_reader import ParsedThreatEntry

        entry = ParsedThreatEntry(
            id="THREAT-001",
            category="Spoofing",
            component="API",
            description="Test",
            attack_vector="Vector",
            impact="Impact",
            severity="high",
            cvss_min=7.0,
            cvss_max=8.9,
        )

        assert entry.id == "THREAT-001"
        assert entry.category == "Spoofing"
        assert entry.severity == "high"

    def test_dataclass_fields(self):
        """Test all expected fields exist."""
        from securevibes_mcp.agents.threat_model_reader import ParsedThreatEntry

        entry = ParsedThreatEntry(
            id="THREAT-001",
            category="Tampering",
            component="Database",
            description="SQL Injection",
            attack_vector="Malformed input",
            impact="Data breach",
            severity="critical",
            cvss_min=9.0,
            cvss_max=10.0,
        )

        assert hasattr(entry, "id")
        assert hasattr(entry, "category")
        assert hasattr(entry, "component")
        assert hasattr(entry, "description")
        assert hasattr(entry, "attack_vector")
        assert hasattr(entry, "impact")
        assert hasattr(entry, "severity")
        assert hasattr(entry, "cvss_min")
        assert hasattr(entry, "cvss_max")


class TestThreatModelReaderParsing:
    """Tests for ThreatModelReader parsing to structured objects."""

    def test_get_threats_returns_list(self, tmp_path: Path):
        """Test get_threats returns list of ParsedThreatEntry."""
        from securevibes_mcp.agents.threat_model_reader import (
            ParsedThreatEntry,
            ThreatModelReader,
        )

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0",
            "generated_at": "2026-01-13T00:00:00Z",
            "project_path": str(tmp_path),
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "Spoofing",
                    "component": "API",
                    "description": "Test",
                    "attack_vector": "Vector",
                    "impact": "Impact",
                    "severity": "high",
                    "cvss_range": {"min": 7.0, "max": 8.9},
                }
            ],
            "summary": {"total": 1},
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        reader = ThreatModelReader(root_path=tmp_path)
        threats = reader.get_threats()

        assert len(threats) == 1
        assert isinstance(threats[0], ParsedThreatEntry)
        assert threats[0].id == "THREAT-001"

    def test_get_threats_empty_when_no_artifact(self, tmp_path: Path):
        """Test get_threats returns empty list when artifact missing."""
        from securevibes_mcp.agents.threat_model_reader import ThreatModelReader

        reader = ThreatModelReader(root_path=tmp_path)
        threats = reader.get_threats()

        assert threats == []

    def test_get_threats_multiple_entries(self, tmp_path: Path):
        """Test parsing multiple threat entries."""
        from securevibes_mcp.agents.threat_model_reader import ThreatModelReader

        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0",
            "generated_at": "2026-01-13T00:00:00Z",
            "project_path": str(tmp_path),
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "Spoofing",
                    "component": "API",
                    "description": "Auth bypass",
                    "attack_vector": "Stolen token",
                    "impact": "Unauthorized access",
                    "severity": "high",
                    "cvss_range": {"min": 7.0, "max": 8.9},
                },
                {
                    "id": "THREAT-002",
                    "category": "Tampering",
                    "component": "Database",
                    "description": "SQL injection",
                    "attack_vector": "Malformed input",
                    "impact": "Data corruption",
                    "severity": "critical",
                    "cvss_range": {"min": 9.0, "max": 10.0},
                },
            ],
            "summary": {"total": 2},
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        reader = ThreatModelReader(root_path=tmp_path)
        threats = reader.get_threats()

        assert len(threats) == 2
        assert threats[0].id == "THREAT-001"
        assert threats[1].id == "THREAT-002"
        assert threats[0].category == "Spoofing"
        assert threats[1].category == "Tampering"
