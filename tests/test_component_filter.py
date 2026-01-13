"""Tests for component filtering in threat analysis."""

from securevibes_mcp.agents.security_parser import Component


class TestComponentFilter:
    """Tests for ComponentFilter class."""

    def test_filter_creation(self):
        """Test that ComponentFilter can be created."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        filter_ = ComponentFilter()
        assert filter_ is not None

    def test_filter_with_component_names(self):
        """Test filtering components by name list."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="User API", component_type="api", description="User API"),
            Component(name="Auth Service", component_type="authentication", description="Auth"),
            Component(name="Database", component_type="data_store", description="DB"),
        ]
        filter_ = ComponentFilter(focus_components=["User API", "Database"])

        result = filter_.filter(components)

        assert len(result) == 2
        names = {c.name for c in result}
        assert "User API" in names
        assert "Database" in names
        assert "Auth Service" not in names

    def test_filter_empty_focus_returns_all(self):
        """Test that empty focus_components returns all components."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="API", component_type="api", description="API"),
            Component(name="DB", component_type="data_store", description="DB"),
        ]
        filter_ = ComponentFilter(focus_components=[])

        result = filter_.filter(components)

        assert len(result) == 2

    def test_filter_none_focus_returns_all(self):
        """Test that None focus_components returns all components."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="API", component_type="api", description="API"),
            Component(name="DB", component_type="data_store", description="DB"),
        ]
        filter_ = ComponentFilter(focus_components=None)

        result = filter_.filter(components)

        assert len(result) == 2

    def test_filter_no_match_returns_empty(self):
        """Test filtering with no matching components."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="API", component_type="api", description="API"),
            Component(name="DB", component_type="data_store", description="DB"),
        ]
        filter_ = ComponentFilter(focus_components=["NonExistent"])

        result = filter_.filter(components)

        assert len(result) == 0

    def test_filter_case_sensitive(self):
        """Test that filtering is case-sensitive by default."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="User API", component_type="api", description="API"),
        ]
        filter_ = ComponentFilter(focus_components=["user api"])

        result = filter_.filter(components)

        assert len(result) == 0

    def test_filter_case_insensitive_option(self):
        """Test case-insensitive filtering option."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="User API", component_type="api", description="API"),
        ]
        filter_ = ComponentFilter(focus_components=["user api"], case_insensitive=True)

        result = filter_.filter(components)

        assert len(result) == 1

    def test_filter_partial_match_not_supported(self):
        """Test that partial matching is not done."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="User API", component_type="api", description="API"),
        ]
        filter_ = ComponentFilter(focus_components=["User"])

        result = filter_.filter(components)

        assert len(result) == 0

    def test_filter_empty_components_returns_empty(self):
        """Test filtering empty component list."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        filter_ = ComponentFilter(focus_components=["API"])
        result = filter_.filter([])

        assert len(result) == 0

    def test_filter_preserves_order(self):
        """Test that filtered results preserve original order."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="A", component_type="api", description="A"),
            Component(name="B", component_type="api", description="B"),
            Component(name="C", component_type="api", description="C"),
        ]
        filter_ = ComponentFilter(focus_components=["C", "A"])

        result = filter_.filter(components)

        # Order should match original list, not focus_components order
        assert result[0].name == "A"
        assert result[1].name == "C"


class TestComponentFilterValidation:
    """Tests for component filter validation."""

    def test_validate_focus_components_valid(self):
        """Test validating valid focus_components."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="API", component_type="api", description="API"),
            Component(name="DB", component_type="data_store", description="DB"),
        ]
        filter_ = ComponentFilter(focus_components=["API", "DB"])

        valid, invalid = filter_.validate(components)

        assert valid == ["API", "DB"]
        assert invalid == []

    def test_validate_focus_components_some_invalid(self):
        """Test validation with some invalid component names."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="API", component_type="api", description="API"),
        ]
        filter_ = ComponentFilter(focus_components=["API", "NonExistent"])

        valid, invalid = filter_.validate(components)

        assert valid == ["API"]
        assert invalid == ["NonExistent"]

    def test_validate_empty_focus_returns_empty_lists(self):
        """Test validation with empty focus returns empty lists."""
        from securevibes_mcp.agents.component_filter import ComponentFilter

        components = [
            Component(name="API", component_type="api", description="API"),
        ]
        filter_ = ComponentFilter(focus_components=[])

        valid, invalid = filter_.validate(components)

        assert valid == []
        assert invalid == []
