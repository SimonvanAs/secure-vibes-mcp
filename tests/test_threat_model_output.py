"""Tests for THREAT_MODEL.json output."""

import json
from pathlib import Path

from securevibes_mcp.agents.stride_analyzer import ThreatFinding


class TestThreatModelSerializer:
    """Tests for ThreatModelSerializer class."""

    def test_serializer_creation(self):
        """Test that ThreatModelSerializer can be created."""
        from securevibes_mcp.agents.threat_model_output import ThreatModelSerializer

        serializer = ThreatModelSerializer()
        assert serializer is not None

    def test_serialize_to_json_string(self):
        """Test serializing ThreatModel to JSON string."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder
        from securevibes_mcp.agents.threat_model_output import ThreatModelSerializer

        builder = ThreatModelBuilder(project_path="/test/path")
        model = builder.build([])

        serializer = ThreatModelSerializer()
        json_str = serializer.serialize(model)

        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["version"] == "1.0"

    def test_serialize_includes_all_fields(self):
        """Test that serialized JSON includes all required fields."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder
        from securevibes_mcp.agents.threat_model_output import ThreatModelSerializer

        builder = ThreatModelBuilder(project_path="/test/project")
        findings = [
            ThreatFinding(
                category="Spoofing",
                component="API",
                description="Test threat",
                attack_vector="Test vector",
                impact="Test impact",
                severity="high",
            ),
        ]
        model = builder.build(findings)

        serializer = ThreatModelSerializer()
        json_str = serializer.serialize(model)
        parsed = json.loads(json_str)

        assert "version" in parsed
        assert "generated_at" in parsed
        assert "project_path" in parsed
        assert "threats" in parsed
        assert "summary" in parsed
        assert len(parsed["threats"]) == 1

    def test_serialize_threat_entry_fields(self):
        """Test that threat entries have all required fields."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder
        from securevibes_mcp.agents.threat_model_output import ThreatModelSerializer

        builder = ThreatModelBuilder(project_path="/test/path")
        findings = [
            ThreatFinding(
                category="Tampering",
                component="Database",
                description="SQL injection",
                attack_vector="Malformed input",
                impact="Data corruption",
                severity="critical",
            ),
        ]
        model = builder.build(findings)

        serializer = ThreatModelSerializer()
        json_str = serializer.serialize(model)
        parsed = json.loads(json_str)
        threat = parsed["threats"][0]

        assert threat["id"].startswith("THREAT-")
        assert threat["category"] == "Tampering"
        assert threat["component"] == "Database"
        assert threat["description"] == "SQL injection"
        assert threat["attack_vector"] == "Malformed input"
        assert threat["impact"] == "Data corruption"
        assert threat["severity"] == "critical"
        assert "cvss_range" in threat
        assert threat["cvss_range"]["min"] == 9.0
        assert threat["cvss_range"]["max"] == 10.0

    def test_serialize_pretty_print(self):
        """Test that JSON is pretty-printed with indentation."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder
        from securevibes_mcp.agents.threat_model_output import ThreatModelSerializer

        builder = ThreatModelBuilder(project_path="/test/path")
        model = builder.build([])

        serializer = ThreatModelSerializer()
        json_str = serializer.serialize(model)

        # Pretty-printed JSON has newlines
        assert "\n" in json_str
        # And indentation
        assert "  " in json_str


class TestThreatModelWriter:
    """Tests for ThreatModelWriter class."""

    def test_writer_creation(self, tmp_path: Path):
        """Test that ThreatModelWriter can be created."""
        from securevibes_mcp.agents.threat_model_output import ThreatModelWriter

        writer = ThreatModelWriter(root_path=tmp_path)
        assert writer is not None

    def test_write_to_storage(self, tmp_path: Path):
        """Test writing threat model to storage."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder
        from securevibes_mcp.agents.threat_model_output import ThreatModelWriter

        builder = ThreatModelBuilder(project_path=str(tmp_path))
        model = builder.build([])

        writer = ThreatModelWriter(root_path=tmp_path)
        result = writer.write(model)

        assert result is True
        # Verify file was created in .securevibes
        artifact_path = tmp_path / ".securevibes" / "THREAT_MODEL.json"
        assert artifact_path.exists()

    def test_write_creates_valid_json(self, tmp_path: Path):
        """Test that written file contains valid JSON."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder
        from securevibes_mcp.agents.threat_model_output import ThreatModelWriter

        builder = ThreatModelBuilder(project_path=str(tmp_path))
        findings = [
            ThreatFinding(
                category="Spoofing",
                component="API",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="high",
            ),
        ]
        model = builder.build(findings)

        writer = ThreatModelWriter(root_path=tmp_path)
        writer.write(model)

        artifact_path = tmp_path / ".securevibes" / "THREAT_MODEL.json"
        content = artifact_path.read_text()
        parsed = json.loads(content)

        assert parsed["version"] == "1.0"
        assert len(parsed["threats"]) == 1

    def test_write_overwrites_existing(self, tmp_path: Path):
        """Test that writing overwrites existing file."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder
        from securevibes_mcp.agents.threat_model_output import ThreatModelWriter

        builder = ThreatModelBuilder(project_path=str(tmp_path))

        # Write first model with no threats
        model1 = builder.build([])
        writer = ThreatModelWriter(root_path=tmp_path)
        writer.write(model1)

        # Write second model with threats
        builder2 = ThreatModelBuilder(project_path=str(tmp_path))
        findings = [
            ThreatFinding(
                category="Spoofing",
                component="API",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="high",
            ),
        ]
        model2 = builder2.build(findings)
        writer.write(model2)

        # Verify second model is written
        artifact_path = tmp_path / ".securevibes" / "THREAT_MODEL.json"
        content = artifact_path.read_text()
        parsed = json.loads(content)

        assert len(parsed["threats"]) == 1

    def test_get_artifact_path(self, tmp_path: Path):
        """Test getting the artifact path."""
        from securevibes_mcp.agents.threat_model_output import ThreatModelWriter

        writer = ThreatModelWriter(root_path=tmp_path)
        path = writer.get_artifact_path()

        assert str(path).endswith("THREAT_MODEL.json")
        assert ".securevibes" in str(path)
