"""Tests for codebase scanning functionality."""

from pathlib import Path


class TestCodebaseScanner:
    """Tests for CodebaseScanner class."""

    def test_scanner_import(self):
        """Test that CodebaseScanner can be imported."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        assert CodebaseScanner is not None

    def test_scanner_creation(self, tmp_path: Path):
        """Test that scanner can be created with a path."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        scanner = CodebaseScanner(tmp_path)
        assert scanner.root_path == tmp_path

    def test_scan_returns_result(self, tmp_path: Path):
        """Test that scan returns a ScanResult."""
        from securevibes_mcp.agents.scanner import CodebaseScanner, ScanResult

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert isinstance(result, ScanResult)


class TestFileTreeWalker:
    """Tests for file tree walking."""

    def test_scan_finds_files(self, tmp_path: Path):
        """Test that scan finds files in directory."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        # Create some files
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert result.file_count >= 2

    def test_scan_walks_subdirectories(self, tmp_path: Path):
        """Test that scan walks into subdirectories."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        # Create nested structure
        subdir = tmp_path / "src"
        subdir.mkdir()
        (subdir / "app.py").write_text("# app")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert result.file_count >= 1

    def test_scan_respects_gitignore(self, tmp_path: Path):
        """Test that scan respects .gitignore patterns."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        # Create .gitignore
        (tmp_path / ".gitignore").write_text("*.log\nnode_modules/\n")

        # Create files that should be ignored
        (tmp_path / "debug.log").write_text("log content")
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "package.json").write_text("{}")

        # Create file that should be included
        (tmp_path / "main.py").write_text("# main")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        # Should find main.py and .gitignore but not debug.log or node_modules/
        assert "debug.log" not in [f.name for f in result.files]
        assert not any("node_modules" in str(f) for f in result.files)

    def test_scan_ignores_common_dirs(self, tmp_path: Path):
        """Test that scan ignores common non-source directories."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        # Create directories that should be ignored
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("[core]")
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "cache.pyc").write_text("cache")
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "lib.py").write_text("lib")

        # Create file that should be included
        (tmp_path / "main.py").write_text("# main")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        file_paths = [str(f) for f in result.files]
        assert not any(".git" in p for p in file_paths)
        assert not any("__pycache__" in p for p in file_paths)
        assert not any(".venv" in p for p in file_paths)


class TestLanguageDetection:
    """Tests for programming language detection."""

    def test_detect_python(self, tmp_path: Path):
        """Test detection of Python files."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert "Python" in result.languages

    def test_detect_javascript(self, tmp_path: Path):
        """Test detection of JavaScript files."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "app.js").write_text("console.log('hi')")
        (tmp_path / "index.ts").write_text("const x: number = 1")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert "JavaScript" in result.languages or "TypeScript" in result.languages

    def test_detect_multiple_languages(self, tmp_path: Path):
        """Test detection of multiple languages."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("# python")
        (tmp_path / "app.js").write_text("// javascript")
        (tmp_path / "lib.go").write_text("package main")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert len(result.languages) >= 3

    def test_language_file_counts(self, tmp_path: Path):
        """Test that language detection includes file counts."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "a.py").write_text("# a")
        (tmp_path / "b.py").write_text("# b")
        (tmp_path / "c.py").write_text("# c")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert result.language_stats["Python"] == 3


class TestFrameworkDetection:
    """Tests for framework detection from manifest files."""

    def test_detect_flask(self, tmp_path: Path):
        """Test detection of Flask framework."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "requirements.txt").write_text("flask==2.0.0\nrequests\n")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert "Flask" in result.frameworks

    def test_detect_django(self, tmp_path: Path):
        """Test detection of Django framework."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "requirements.txt").write_text("django>=4.0\n")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert "Django" in result.frameworks

    def test_detect_react_from_package_json(self, tmp_path: Path):
        """Test detection of React from package.json."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "package.json").write_text(
            '{"dependencies": {"react": "^18.0.0"}}'
        )

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert "React" in result.frameworks

    def test_detect_fastapi(self, tmp_path: Path):
        """Test detection of FastAPI framework."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["fastapi>=0.100.0"]\n'
        )

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert "FastAPI" in result.frameworks

    def test_detect_express(self, tmp_path: Path):
        """Test detection of Express framework."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "package.json").write_text(
            '{"dependencies": {"express": "^4.18.0"}}'
        )

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert "Express" in result.frameworks

    def test_no_frameworks_detected(self, tmp_path: Path):
        """Test when no frameworks are detected."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("print('hello')")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert result.frameworks == []


class TestScanResult:
    """Tests for ScanResult data class."""

    def test_scan_result_has_required_fields(self, tmp_path: Path):
        """Test that ScanResult has all required fields."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("# main")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()

        assert hasattr(result, "file_count")
        assert hasattr(result, "files")
        assert hasattr(result, "languages")
        assert hasattr(result, "language_stats")
        assert hasattr(result, "frameworks")
        assert hasattr(result, "root_path")

    def test_scan_result_to_dict(self, tmp_path: Path):
        """Test that ScanResult can be converted to dict."""
        from securevibes_mcp.agents.scanner import CodebaseScanner

        (tmp_path / "main.py").write_text("# main")

        scanner = CodebaseScanner(tmp_path)
        result = scanner.scan()
        result_dict = result.to_dict()

        assert "file_count" in result_dict
        assert "languages" in result_dict
        assert "frameworks" in result_dict
