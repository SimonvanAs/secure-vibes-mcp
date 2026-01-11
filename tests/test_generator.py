"""Tests for SECURITY.md generation."""

from pathlib import Path


class TestSecurityDocGenerator:
    """Tests for SecurityDocGenerator class."""

    def test_generator_import(self):
        """Test that SecurityDocGenerator can be imported."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator

        assert SecurityDocGenerator is not None

    def test_generator_creation(self, tmp_path: Path):
        """Test that generator can be created with scan result."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        scanner = CodebaseScanner(tmp_path)
        scan_result = scanner.scan()

        generator = SecurityDocGenerator(scan_result)
        assert generator.scan_result == scan_result

    def test_generate_returns_string(self, tmp_path: Path):
        """Test that generate returns a markdown string."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("print('hello')")

        scanner = CodebaseScanner(tmp_path)
        scan_result = scanner.scan()

        generator = SecurityDocGenerator(scan_result)
        result = generator.generate()

        assert isinstance(result, str)
        assert len(result) > 0


class TestSecurityDocStructure:
    """Tests for SECURITY.md document structure."""

    def test_has_title(self, tmp_path: Path):
        """Test that document has a title."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("# app")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        assert "# Security Assessment" in doc or "# SECURITY" in doc

    def test_has_overview_section(self, tmp_path: Path):
        """Test that document has an overview section."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("# app")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        assert "## Overview" in doc or "## Project Overview" in doc

    def test_has_architecture_section(self, tmp_path: Path):
        """Test that document has an architecture section."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("# app")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        assert "## Architecture" in doc or "## Technology Stack" in doc

    def test_has_security_section(self, tmp_path: Path):
        """Test that document has security observations section."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("# app")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        assert "## Security" in doc or "Security Considerations" in doc


class TestArchitectureOverview:
    """Tests for architecture overview generation."""

    def test_includes_languages(self, tmp_path: Path):
        """Test that architecture includes detected languages."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "app.js").write_text("console.log('hi')")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        assert "Python" in doc
        assert "JavaScript" in doc

    def test_includes_frameworks(self, tmp_path: Path):
        """Test that architecture includes detected frameworks."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        (tmp_path / "app.py").write_text("from flask import Flask")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        assert "Flask" in doc

    def test_includes_file_count(self, tmp_path: Path):
        """Test that architecture includes file count."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "a.py").write_text("# a")
        (tmp_path / "b.py").write_text("# b")
        (tmp_path / "c.py").write_text("# c")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        # Should mention file count somewhere
        assert "3" in doc or "files" in doc.lower()


class TestSecurityObservations:
    """Tests for security observations generation."""

    def test_flask_observations(self, tmp_path: Path):
        """Test security observations for Flask projects."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        # Should include Flask-specific security considerations
        assert "session" in doc.lower() or "csrf" in doc.lower() or "flask" in doc.lower()

    def test_django_observations(self, tmp_path: Path):
        """Test security observations for Django projects."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "requirements.txt").write_text("django>=4.0\n")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        # Should include Django-specific security considerations
        assert "django" in doc.lower()

    def test_express_observations(self, tmp_path: Path):
        """Test security observations for Express projects."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.18.0"}}')

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        # Should include Express-specific security considerations
        assert "express" in doc.lower()

    def test_no_frameworks_has_general_observations(self, tmp_path: Path):
        """Test that projects without frameworks get general observations."""
        from securevibes_mcp.agents.generator import SecurityDocGenerator
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("print('hello')")

        scanner = CodebaseScanner(tmp_path)
        generator = SecurityDocGenerator(scanner.scan())
        doc = generator.generate()

        # Should still have security section with general guidance
        assert "security" in doc.lower()
