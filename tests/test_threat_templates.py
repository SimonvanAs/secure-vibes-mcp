"""Tests for threat template system."""


class TestThreatTemplate:
    """Tests for ThreatTemplate dataclass."""

    def test_threat_template_creation(self):
        """Test that ThreatTemplate can be created."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplate

        template = ThreatTemplate(
            category="Spoofing",
            component_type="api",
            description="Identity spoofing via forged tokens",
            attack_vector="Token manipulation",
            impact="Unauthorized access",
            severity="high",
        )
        assert template.category == "Spoofing"
        assert template.component_type == "api"

    def test_threat_template_has_all_fields(self):
        """Test that ThreatTemplate has all required fields."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplate

        template = ThreatTemplate(
            category="Tampering",
            component_type="data_store",
            description="Data tampering",
            attack_vector="SQL injection",
            impact="Data corruption",
            severity="critical",
        )
        assert template.category is not None
        assert template.component_type is not None
        assert template.description is not None
        assert template.attack_vector is not None
        assert template.impact is not None
        assert template.severity is not None


class TestThreatTemplateRegistry:
    """Tests for ThreatTemplateRegistry."""

    def test_registry_creation(self):
        """Test that ThreatTemplateRegistry can be created."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry

        registry = ThreatTemplateRegistry()
        assert registry is not None

    def test_registry_has_api_templates(self):
        """Test that registry has templates for API components."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry

        registry = ThreatTemplateRegistry()
        templates = registry.get_templates_for_type("api")

        assert len(templates) > 0
        assert all(t.component_type == "api" for t in templates)

    def test_registry_has_data_store_templates(self):
        """Test that registry has templates for data store components."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry

        registry = ThreatTemplateRegistry()
        templates = registry.get_templates_for_type("data_store")

        assert len(templates) > 0
        assert all(t.component_type == "data_store" for t in templates)

    def test_registry_has_authentication_templates(self):
        """Test that registry has templates for authentication components."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry

        registry = ThreatTemplateRegistry()
        templates = registry.get_templates_for_type("authentication")

        assert len(templates) > 0
        assert all(t.component_type == "authentication" for t in templates)

    def test_registry_has_external_integration_templates(self):
        """Test that registry has templates for external integration components."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry

        registry = ThreatTemplateRegistry()
        templates = registry.get_templates_for_type("external_integration")

        assert len(templates) > 0
        assert all(t.component_type == "external_integration" for t in templates)

    def test_registry_returns_empty_for_unknown_type(self):
        """Test that registry returns empty list for unknown component type."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry

        registry = ThreatTemplateRegistry()
        templates = registry.get_templates_for_type("unknown_type")

        assert templates == []

    def test_api_templates_cover_stride_categories(self):
        """Test that API templates cover all STRIDE categories."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry

        registry = ThreatTemplateRegistry()
        templates = registry.get_templates_for_type("api")
        categories = {t.category for t in templates}

        assert "Spoofing" in categories
        assert "Tampering" in categories
        assert "Repudiation" in categories
        assert "InfoDisclosure" in categories
        assert "DoS" in categories
        assert "EoP" in categories

    def test_get_all_templates(self):
        """Test getting all templates from registry."""
        from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry

        registry = ThreatTemplateRegistry()
        all_templates = registry.get_all_templates()

        assert len(all_templates) > 0
        # Should have templates for multiple component types
        component_types = {t.component_type for t in all_templates}
        assert len(component_types) >= 4


class TestSTRIDECategories:
    """Tests for STRIDE category constants."""

    def test_stride_categories_defined(self):
        """Test that all STRIDE categories are defined."""
        from securevibes_mcp.agents.threat_templates import STRIDE_CATEGORIES

        assert "Spoofing" in STRIDE_CATEGORIES
        assert "Tampering" in STRIDE_CATEGORIES
        assert "Repudiation" in STRIDE_CATEGORIES
        assert "InfoDisclosure" in STRIDE_CATEGORIES
        assert "DoS" in STRIDE_CATEGORIES
        assert "EoP" in STRIDE_CATEGORIES

    def test_stride_categories_count(self):
        """Test that there are exactly 6 STRIDE categories."""
        from securevibes_mcp.agents.threat_templates import STRIDE_CATEGORIES

        assert len(STRIDE_CATEGORIES) == 6
