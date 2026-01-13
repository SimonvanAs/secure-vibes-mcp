"""Tests for STRIDE analyzer."""

from securevibes_mcp.agents.security_parser import Component


class TestSTRIDEAnalyzer:
    """Tests for STRIDEAnalyzer class."""

    def test_analyzer_creation(self):
        """Test that STRIDEAnalyzer can be created."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        assert analyzer is not None

    def test_analyze_component_returns_threats(self):
        """Test that analyzing a component returns threats."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        component = Component(
            name="User API",
            component_type="api",
            description="REST API for user management",
        )

        threats = analyzer.analyze_component(component)

        assert isinstance(threats, list)
        assert len(threats) > 0

    def test_analyze_api_component_returns_6_threats(self):
        """Test that API component analysis returns threats for all 6 STRIDE categories."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        component = Component(
            name="User API",
            component_type="api",
            description="REST API for user management",
        )

        threats = analyzer.analyze_component(component)
        categories = {t.category for t in threats}

        assert len(categories) == 6
        assert "Spoofing" in categories
        assert "Tampering" in categories
        assert "Repudiation" in categories
        assert "InfoDisclosure" in categories
        assert "DoS" in categories
        assert "EoP" in categories

    def test_analyze_data_store_component(self):
        """Test analyzing a data store component."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        component = Component(
            name="PostgreSQL",
            component_type="data_store",
            description="PostgreSQL database",
        )

        threats = analyzer.analyze_component(component)
        categories = {t.category for t in threats}

        assert len(threats) >= 6
        assert "Spoofing" in categories

    def test_analyze_auth_component(self):
        """Test analyzing an authentication component."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        component = Component(
            name="JWT Auth",
            component_type="authentication",
            description="JWT authentication service",
        )

        threats = analyzer.analyze_component(component)

        assert len(threats) >= 6

    def test_threat_has_component_name(self):
        """Test that generated threats include the component name."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        component = Component(
            name="User API",
            component_type="api",
            description="REST API",
        )

        threats = analyzer.analyze_component(component)

        for threat in threats:
            assert threat.component == "User API"

    def test_threat_has_required_fields(self):
        """Test that generated threats have all required fields."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        component = Component(
            name="API",
            component_type="api",
            description="API",
        )

        threats = analyzer.analyze_component(component)

        for threat in threats:
            assert threat.category is not None
            assert threat.component is not None
            assert threat.description is not None
            assert threat.attack_vector is not None
            assert threat.impact is not None
            assert threat.severity is not None

    def test_analyze_unknown_component_type(self):
        """Test analyzing a component with unknown type returns service templates."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        component = Component(
            name="Unknown",
            component_type="unknown_type",
            description="Unknown component",
        )

        threats = analyzer.analyze_component(component)

        # Should return empty list or generic threats
        assert isinstance(threats, list)


class TestSTRIDEAnalyzerBatch:
    """Tests for batch analysis of multiple components."""

    def test_analyze_components_returns_all_threats(self):
        """Test analyzing multiple components returns threats for each."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        components = [
            Component(name="API", component_type="api", description="API"),
            Component(name="DB", component_type="data_store", description="Database"),
        ]

        all_threats = analyzer.analyze_components(components)

        assert len(all_threats) >= 12  # At least 6 threats per component

    def test_analyze_empty_components_returns_empty(self):
        """Test analyzing empty component list returns empty threats."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        threats = analyzer.analyze_components([])

        assert threats == []

    def test_threats_have_unique_component_names(self):
        """Test that threats retain their source component names."""
        from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer

        analyzer = STRIDEAnalyzer()
        components = [
            Component(name="User API", component_type="api", description="User API"),
            Component(name="User DB", component_type="data_store", description="DB"),
        ]

        all_threats = analyzer.analyze_components(components)
        component_names = {t.component for t in all_threats}

        assert "User API" in component_names
        assert "User DB" in component_names


class TestThreatFinding:
    """Tests for ThreatFinding dataclass."""

    def test_threat_finding_creation(self):
        """Test that ThreatFinding can be created."""
        from securevibes_mcp.agents.stride_analyzer import ThreatFinding

        finding = ThreatFinding(
            category="Spoofing",
            component="API",
            description="Identity spoofing",
            attack_vector="Token theft",
            impact="Unauthorized access",
            severity="high",
        )

        assert finding.category == "Spoofing"
        assert finding.component == "API"
        assert finding.severity == "high"

    def test_threat_finding_to_dict(self):
        """Test that ThreatFinding can be converted to dict."""
        from securevibes_mcp.agents.stride_analyzer import ThreatFinding

        finding = ThreatFinding(
            category="Tampering",
            component="Database",
            description="SQL injection",
            attack_vector="Malformed input",
            impact="Data corruption",
            severity="critical",
        )

        d = finding.to_dict()

        assert d["category"] == "Tampering"
        assert d["component"] == "Database"
        assert d["severity"] == "critical"
