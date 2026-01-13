"""Tests for severity classification system."""


class TestSeverityLevels:
    """Tests for severity level constants."""

    def test_severity_levels_defined(self):
        """Test that all severity levels are defined."""
        from securevibes_mcp.agents.severity import SEVERITY_LEVELS

        assert "critical" in SEVERITY_LEVELS
        assert "high" in SEVERITY_LEVELS
        assert "medium" in SEVERITY_LEVELS
        assert "low" in SEVERITY_LEVELS

    def test_severity_levels_count(self):
        """Test that there are exactly 4 severity levels."""
        from securevibes_mcp.agents.severity import SEVERITY_LEVELS

        assert len(SEVERITY_LEVELS) == 4

    def test_severity_levels_are_lowercase(self):
        """Test that severity levels are lowercase."""
        from securevibes_mcp.agents.severity import SEVERITY_LEVELS

        for level in SEVERITY_LEVELS:
            assert level == level.lower()


class TestSeverityClassifier:
    """Tests for SeverityClassifier class."""

    def test_classifier_creation(self):
        """Test that SeverityClassifier can be created."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()
        assert classifier is not None

    def test_validate_severity_valid(self):
        """Test validating valid severity levels."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.validate("critical") is True
        assert classifier.validate("high") is True
        assert classifier.validate("medium") is True
        assert classifier.validate("low") is True

    def test_validate_severity_invalid(self):
        """Test validating invalid severity levels."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.validate("invalid") is False
        assert classifier.validate("extreme") is False
        assert classifier.validate("") is False

    def test_validate_severity_case_insensitive(self):
        """Test that severity validation is case insensitive."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.validate("Critical") is True
        assert classifier.validate("HIGH") is True
        assert classifier.validate("MeDiUm") is True

    def test_normalize_severity(self):
        """Test normalizing severity to lowercase."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.normalize("CRITICAL") == "critical"
        assert classifier.normalize("High") == "high"
        assert classifier.normalize("medium") == "medium"

    def test_normalize_invalid_severity_returns_medium(self):
        """Test that invalid severity normalizes to medium."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.normalize("invalid") == "medium"
        assert classifier.normalize("") == "medium"

    def test_get_cvss_range(self):
        """Test getting CVSS score range for severity."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.get_cvss_range("critical") == (9.0, 10.0)
        assert classifier.get_cvss_range("high") == (7.0, 8.9)
        assert classifier.get_cvss_range("medium") == (4.0, 6.9)
        assert classifier.get_cvss_range("low") == (0.1, 3.9)

    def test_get_cvss_range_unknown_returns_medium_range(self):
        """Test that unknown severity returns medium CVSS range."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.get_cvss_range("unknown") == (4.0, 6.9)

    def test_compare_severity(self):
        """Test comparing severity levels."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.compare("critical", "high") > 0
        assert classifier.compare("high", "medium") > 0
        assert classifier.compare("medium", "low") > 0
        assert classifier.compare("low", "critical") < 0
        assert classifier.compare("high", "high") == 0

    def test_get_severity_order(self):
        """Test getting numeric order for severity."""
        from securevibes_mcp.agents.severity import SeverityClassifier

        classifier = SeverityClassifier()

        assert classifier.get_order("critical") == 4
        assert classifier.get_order("high") == 3
        assert classifier.get_order("medium") == 2
        assert classifier.get_order("low") == 1
        assert classifier.get_order("unknown") == 0


class TestSeverityApplied:
    """Tests for applying severity to threats."""

    def test_classify_threat_preserves_existing_severity(self):
        """Test that existing valid severity is preserved."""
        from securevibes_mcp.agents.severity import SeverityClassifier
        from securevibes_mcp.agents.stride_analyzer import ThreatFinding

        classifier = SeverityClassifier()
        threat = ThreatFinding(
            category="Spoofing",
            component="API",
            description="Test threat",
            attack_vector="Test vector",
            impact="Test impact",
            severity="high",
        )

        result = classifier.classify_threat(threat)
        assert result.severity == "high"

    def test_classify_threat_normalizes_severity(self):
        """Test that severity is normalized."""
        from securevibes_mcp.agents.severity import SeverityClassifier
        from securevibes_mcp.agents.stride_analyzer import ThreatFinding

        classifier = SeverityClassifier()
        threat = ThreatFinding(
            category="Spoofing",
            component="API",
            description="Test threat",
            attack_vector="Test vector",
            impact="Test impact",
            severity="HIGH",
        )

        result = classifier.classify_threat(threat)
        assert result.severity == "high"

    def test_classify_threats_batch(self):
        """Test classifying multiple threats."""
        from securevibes_mcp.agents.severity import SeverityClassifier
        from securevibes_mcp.agents.stride_analyzer import ThreatFinding

        classifier = SeverityClassifier()
        threats = [
            ThreatFinding(
                category="Spoofing",
                component="API",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="CRITICAL",
            ),
            ThreatFinding(
                category="Tampering",
                component="DB",
                description="Test",
                attack_vector="Test",
                impact="Test",
                severity="low",
            ),
        ]

        results = classifier.classify_threats(threats)

        assert len(results) == 2
        assert results[0].severity == "critical"
        assert results[1].severity == "low"
