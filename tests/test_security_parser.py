"""Tests for SECURITY.md parser."""

from pathlib import Path

from securevibes_mcp.storage import ScanStateManager


class TestSecurityDocParser:
    """Tests for SecurityDocParser class."""

    def test_parser_creation(self, tmp_path: Path):
        """Test that SecurityDocParser can be created."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        parser = SecurityDocParser(tmp_path)
        assert parser is not None

    def test_parser_loads_security_md(self, tmp_path: Path):
        """Test that parser loads SECURITY.md from artifacts."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        # Create SECURITY.md artifact
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", "# Security Assessment\n\nTest content")

        parser = SecurityDocParser(tmp_path)
        content = parser.load()

        assert content is not None
        assert "Security Assessment" in content

    def test_parser_returns_none_when_missing(self, tmp_path: Path):
        """Test that parser returns None when SECURITY.md doesn't exist."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        parser = SecurityDocParser(tmp_path)
        content = parser.load()

        assert content is None

    def test_parser_uses_scan_state_manager(self, tmp_path: Path):
        """Test that parser uses ScanStateManager for artifact access."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", "# Test")

        parser = SecurityDocParser(tmp_path)
        assert parser.manager is not None
        assert parser.load() == "# Test"


class TestSecurityDocParserParsing:
    """Tests for parsing SECURITY.md content."""

    def test_parse_returns_parsed_document(self, tmp_path: Path):
        """Test that parse() returns a ParsedSecurityDoc."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", "# Security Assessment\n\n## Project Overview\nTest project")

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()

        assert doc is not None
        assert doc.raw_content is not None

    def test_parse_returns_none_when_missing(self, tmp_path: Path):
        """Test that parse() returns None when artifact missing."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()

        assert doc is None

    def test_parsed_doc_has_sections(self, tmp_path: Path):
        """Test that ParsedSecurityDoc has sections extracted."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Project Overview
A test project with some components.

## Languages
- Python

## Frameworks
- Flask
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()

        assert doc.sections is not None
        assert len(doc.sections) > 0

    def test_parsed_doc_extracts_languages(self, tmp_path: Path):
        """Test that ParsedSecurityDoc extracts languages."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Languages
- Python
- JavaScript
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()

        assert "Python" in doc.languages
        assert "JavaScript" in doc.languages

    def test_parsed_doc_extracts_frameworks(self, tmp_path: Path):
        """Test that ParsedSecurityDoc extracts frameworks."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Frameworks
- Flask
- React
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()

        assert "Flask" in doc.frameworks
        assert "React" in doc.frameworks


class TestComponentExtraction:
    """Tests for component extraction from SECURITY.md."""

    def test_extract_components_returns_list(self, tmp_path: Path):
        """Test that extract_components returns a list of Component objects."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Project Overview
A Flask web application.

## Architecture
The application has a REST API backend.
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        assert isinstance(components, list)

    def test_extract_api_component_from_architecture(self, tmp_path: Path):
        """Test that API components are extracted from architecture section."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Architecture
- REST API endpoints for user management
- Authentication service
- PostgreSQL database
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        component_types = [c.component_type for c in components]
        assert "api" in component_types

    def test_extract_database_component(self, tmp_path: Path):
        """Test that database components are extracted."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Architecture
- PostgreSQL database for persistence
- Redis cache
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        component_types = [c.component_type for c in components]
        assert "data_store" in component_types

    def test_extract_auth_component(self, tmp_path: Path):
        """Test that authentication components are extracted."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Architecture
- JWT authentication service
- OAuth2 integration
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        component_types = [c.component_type for c in components]
        assert "authentication" in component_types

    def test_extract_external_component(self, tmp_path: Path):
        """Test that external integration components are extracted."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Architecture
- Stripe payment integration
- SendGrid email service
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        component_types = [c.component_type for c in components]
        assert "external_integration" in component_types

    def test_component_has_name(self, tmp_path: Path):
        """Test that extracted components have names."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Architecture
- User API endpoints
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        assert len(components) > 0
        assert components[0].name is not None
        assert len(components[0].name) > 0

    def test_component_has_description(self, tmp_path: Path):
        """Test that extracted components have descriptions."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Architecture
- User API endpoints for managing user accounts
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        assert len(components) > 0
        assert components[0].description is not None

    def test_empty_architecture_returns_empty_list(self, tmp_path: Path):
        """Test that missing architecture section returns empty component list."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Project Overview
A simple project.
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        assert components == []

    def test_extract_multiple_components(self, tmp_path: Path):
        """Test extracting multiple components of different types."""
        from securevibes_mcp.agents.security_parser import SecurityDocParser

        content = """# Security Assessment

## Architecture
- REST API for user management
- PostgreSQL database
- JWT authentication
- Stripe payment gateway
"""
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", content)

        parser = SecurityDocParser(tmp_path)
        doc = parser.parse()
        components = doc.extract_components()

        assert len(components) >= 4
        component_types = {c.component_type for c in components}
        assert "api" in component_types
        assert "data_store" in component_types
        assert "authentication" in component_types
        assert "external_integration" in component_types
