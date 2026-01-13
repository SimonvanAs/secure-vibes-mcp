"""Tests for threat model builder."""

from securevibes_mcp.agents.stride_analyzer import ThreatFinding


class TestThreatEntry:
    """Tests for ThreatEntry dataclass."""

    def test_threat_entry_creation(self):
        """Test that ThreatEntry can be created."""
        from securevibes_mcp.agents.threat_model_builder import ThreatEntry

        entry = ThreatEntry(
            id="THREAT-001",
            category="Spoofing",
            component="API",
            description="Test threat",
            attack_vector="Test vector",
            impact="Test impact",
            severity="high",
            cvss_range=(7.0, 8.9),
        )
        assert entry.id == "THREAT-001"
        assert entry.category == "Spoofing"

    def test_threat_entry_to_dict(self):
        """Test that ThreatEntry can be converted to dict."""
        from securevibes_mcp.agents.threat_model_builder import ThreatEntry

        entry = ThreatEntry(
            id="THREAT-002",
            category="Tampering",
            component="Database",
            description="SQL injection",
            attack_vector="Malformed input",
            impact="Data corruption",
            severity="critical",
            cvss_range=(9.0, 10.0),
        )
        d = entry.to_dict()

        assert d["id"] == "THREAT-002"
        assert d["category"] == "Tampering"
        assert d["component"] == "Database"
        assert d["severity"] == "critical"
        assert d["cvss_range"]["min"] == 9.0
        assert d["cvss_range"]["max"] == 10.0


class TestThreatModel:
    """Tests for ThreatModel dataclass."""

    def test_threat_model_creation(self):
        """Test that ThreatModel can be created."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModel

        model = ThreatModel(
            version="1.0",
            generated_at="2026-01-13T12:00:00Z",
            project_path="/test/path",
            threats=[],
            summary={"total": 0},
        )
        assert model.version == "1.0"
        assert model.threats == []

    def test_threat_model_to_dict(self):
        """Test that ThreatModel can be converted to dict."""
        from securevibes_mcp.agents.threat_model_builder import ThreatEntry, ThreatModel

        entry = ThreatEntry(
            id="THREAT-001",
            category="Spoofing",
            component="API",
            description="Test",
            attack_vector="Test",
            impact="Test",
            severity="high",
            cvss_range=(7.0, 8.9),
        )
        model = ThreatModel(
            version="1.0",
            generated_at="2026-01-13T12:00:00Z",
            project_path="/test/path",
            threats=[entry],
            summary={"total": 1},
        )
        d = model.to_dict()

        assert d["version"] == "1.0"
        assert d["project_path"] == "/test/path"
        assert len(d["threats"]) == 1


class TestThreatModelBuilder:
    """Tests for ThreatModelBuilder class."""

    def test_builder_creation(self):
        """Test that ThreatModelBuilder can be created."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")
        assert builder is not None

    def test_generate_threat_id(self):
        """Test generating unique threat IDs."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")

        id1 = builder.generate_threat_id()
        id2 = builder.generate_threat_id()
        id3 = builder.generate_threat_id()

        assert id1 == "THREAT-001"
        assert id2 == "THREAT-002"
        assert id3 == "THREAT-003"

    def test_generate_threat_id_format(self):
        """Test that threat IDs have correct format."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")
        threat_id = builder.generate_threat_id()

        assert threat_id.startswith("THREAT-")
        assert len(threat_id) == 10  # THREAT-001

    def test_build_threat_entry_from_finding(self):
        """Test building a ThreatEntry from a ThreatFinding."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")
        finding = ThreatFinding(
            category="Spoofing",
            component="User API",
            description="Identity spoofing",
            attack_vector="Token theft",
            impact="Unauthorized access",
            severity="high",
        )

        entry = builder.build_threat_entry(finding)

        assert entry.id.startswith("THREAT-")
        assert entry.category == "Spoofing"
        assert entry.component == "User API"
        assert entry.severity == "high"
        assert entry.cvss_range == (7.0, 8.9)

    def test_build_threat_entry_includes_cvss_range(self):
        """Test that ThreatEntry includes CVSS range based on severity."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")

        critical_finding = ThreatFinding(
            category="Tampering",
            component="DB",
            description="Test",
            attack_vector="Test",
            impact="Test",
            severity="critical",
        )
        low_finding = ThreatFinding(
            category="Repudiation",
            component="API",
            description="Test",
            attack_vector="Test",
            impact="Test",
            severity="low",
        )

        critical_entry = builder.build_threat_entry(critical_finding)
        low_entry = builder.build_threat_entry(low_finding)

        assert critical_entry.cvss_range == (9.0, 10.0)
        assert low_entry.cvss_range == (0.1, 3.9)

    def test_build_model_from_findings(self):
        """Test building complete ThreatModel from findings."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/project")
        findings = [
            ThreatFinding(
                category="Spoofing",
                component="API",
                description="Test1",
                attack_vector="Test",
                impact="Test",
                severity="high",
            ),
            ThreatFinding(
                category="Tampering",
                component="DB",
                description="Test2",
                attack_vector="Test",
                impact="Test",
                severity="critical",
            ),
        ]

        model = builder.build(findings)

        assert model.version == "1.0"
        assert model.project_path == "/test/project"
        assert len(model.threats) == 2
        assert model.summary["total"] == 2

    def test_build_model_empty_findings(self):
        """Test building ThreatModel with no findings."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")
        model = builder.build([])

        assert len(model.threats) == 0
        assert model.summary["total"] == 0

    def test_build_model_has_summary_by_severity(self):
        """Test that ThreatModel summary includes counts by severity."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")
        findings = [
            ThreatFinding(
                category="Spoofing",
                component="API",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="critical",
            ),
            ThreatFinding(
                category="Tampering",
                component="DB",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="critical",
            ),
            ThreatFinding(
                category="DoS",
                component="API",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="high",
            ),
        ]

        model = builder.build(findings)

        assert model.summary["critical"] == 2
        assert model.summary["high"] == 1
        assert model.summary["total"] == 3

    def test_build_model_has_summary_by_category(self):
        """Test that ThreatModel summary includes counts by STRIDE category."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")
        findings = [
            ThreatFinding(
                category="Spoofing",
                component="API",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="high",
            ),
            ThreatFinding(
                category="Spoofing",
                component="DB",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="high",
            ),
            ThreatFinding(
                category="Tampering",
                component="API",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="high",
            ),
        ]

        model = builder.build(findings)

        assert model.summary["by_category"]["Spoofing"] == 2
        assert model.summary["by_category"]["Tampering"] == 1

    def test_build_model_has_generated_timestamp(self):
        """Test that ThreatModel has generated timestamp."""
        from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder

        builder = ThreatModelBuilder(project_path="/test/path")
        model = builder.build([])

        assert model.generated_at is not None
        assert "T" in model.generated_at  # ISO format
