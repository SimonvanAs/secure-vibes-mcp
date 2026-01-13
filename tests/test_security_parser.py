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
