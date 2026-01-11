"""Codebase scanning functionality for security assessment."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Directories to always ignore during scanning
IGNORED_DIRS = frozenset({
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    ".venv",
    "venv",
    ".env",
    "env",
    ".tox",
    "dist",
    "build",
    ".eggs",
    "*.egg-info",
})

# Language detection by file extension
LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".h": "C",
    ".swift": "Swift",
    ".scala": "Scala",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
}

# Framework detection patterns
FRAMEWORK_PATTERNS: dict[str, list[tuple[str, str]]] = {
    # Python frameworks (from requirements.txt, pyproject.toml)
    "Flask": [
        ("requirements.txt", r"flask[=<>~\[]"),
        ("pyproject.toml", r"flask[=<>~\[\"]"),
    ],
    "Django": [
        ("requirements.txt", r"django[=<>~\[]"),
        ("pyproject.toml", r"django[=<>~\[\"]"),
    ],
    "FastAPI": [
        ("requirements.txt", r"fastapi[=<>~\[]"),
        ("pyproject.toml", r"fastapi[=<>~\[\"]"),
    ],
    "SQLAlchemy": [
        ("requirements.txt", r"sqlalchemy[=<>~\[]"),
        ("pyproject.toml", r"sqlalchemy[=<>~\[\"]"),
    ],
    # JavaScript/Node frameworks (from package.json)
    "React": [
        ("package.json", r'"react"'),
    ],
    "Vue": [
        ("package.json", r'"vue"'),
    ],
    "Angular": [
        ("package.json", r'"@angular/core"'),
    ],
    "Express": [
        ("package.json", r'"express"'),
    ],
    "Next.js": [
        ("package.json", r'"next"'),
    ],
    # Go frameworks (from go.mod)
    "Gin": [
        ("go.mod", r"github\.com/gin-gonic/gin"),
    ],
    "Echo": [
        ("go.mod", r"github\.com/labstack/echo"),
    ],
}


@dataclass
class ScanResult:
    """Result of a codebase scan.

    Attributes:
        root_path: The root path that was scanned.
        files: List of all scanned file paths.
        file_count: Total number of files scanned.
        languages: List of detected programming languages.
        language_stats: Dictionary mapping languages to file counts.
        frameworks: List of detected frameworks.
    """

    root_path: Path
    files: list[Path] = field(default_factory=list)
    file_count: int = 0
    languages: list[str] = field(default_factory=list)
    language_stats: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary.

        Returns:
            Dictionary representation of the scan result.
        """
        return {
            "root_path": str(self.root_path),
            "file_count": self.file_count,
            "languages": self.languages,
            "language_stats": self.language_stats,
            "frameworks": self.frameworks,
        }


class CodebaseScanner:
    """Scans a codebase to detect languages and frameworks.

    Attributes:
        root_path: The root path of the codebase to scan.
    """

    def __init__(self, root_path: Path) -> None:
        """Initialize the scanner.

        Args:
            root_path: The root path of the codebase to scan.
        """
        self.root_path = root_path
        self._gitignore_patterns: list[str] = []

    def _load_gitignore(self) -> None:
        """Load .gitignore patterns from the root path."""
        gitignore_path = self.root_path / ".gitignore"
        if gitignore_path.exists():
            content = gitignore_path.read_text()
            self._gitignore_patterns = [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.startswith("#")
            ]

    def _should_ignore(self, path: Path) -> bool:
        """Check if a path should be ignored.

        Args:
            path: The path to check.

        Returns:
            True if the path should be ignored.
        """
        # Check against ignored directories
        for part in path.parts:
            if part in IGNORED_DIRS:
                return True
            # Check wildcard patterns in IGNORED_DIRS
            for ignored in IGNORED_DIRS:
                if "*" in ignored:
                    pattern = ignored.replace("*", ".*")
                    if re.match(pattern, part):
                        return True

        # Check against .gitignore patterns
        rel_path = path.relative_to(self.root_path) if path.is_relative_to(self.root_path) else path

        for pattern in self._gitignore_patterns:
            # Handle directory patterns (ending with /)
            if pattern.endswith("/"):
                dir_pattern = pattern.rstrip("/")
                if dir_pattern in rel_path.parts:
                    return True
            # Handle file patterns
            elif "*" in pattern:
                # Convert glob to regex
                regex = pattern.replace(".", r"\.").replace("*", ".*")
                if re.match(regex, rel_path.name):
                    return True
            else:
                # Exact match
                if pattern == rel_path.name or pattern in rel_path.parts:
                    return True

        return False

    def _detect_language(self, path: Path) -> str | None:
        """Detect the programming language of a file.

        Args:
            path: The file path.

        Returns:
            The detected language name, or None if not recognized.
        """
        suffix = path.suffix.lower()
        return LANGUAGE_EXTENSIONS.get(suffix)

    def _detect_frameworks(self) -> list[str]:
        """Detect frameworks from manifest files.

        Returns:
            List of detected framework names.
        """
        frameworks: list[str] = []

        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for filename, pattern in patterns:
                manifest_path = self.root_path / filename
                if manifest_path.exists():
                    try:
                        content = manifest_path.read_text().lower()
                        if re.search(pattern, content, re.IGNORECASE):
                            if framework not in frameworks:
                                frameworks.append(framework)
                            break
                    except (OSError, UnicodeDecodeError):
                        continue

        return frameworks

    def scan(self) -> ScanResult:
        """Scan the codebase.

        Returns:
            ScanResult containing file and language information.
        """
        self._load_gitignore()

        files: list[Path] = []
        language_stats: dict[str, int] = {}

        # Walk the directory tree
        for path in self.root_path.rglob("*"):
            if path.is_file() and not self._should_ignore(path):
                files.append(path)

                # Detect language
                language = self._detect_language(path)
                if language:
                    language_stats[language] = language_stats.get(language, 0) + 1

        # Get unique languages sorted by file count
        languages = sorted(language_stats.keys(), key=lambda x: -language_stats[x])

        # Detect frameworks
        frameworks = self._detect_frameworks()

        return ScanResult(
            root_path=self.root_path,
            files=files,
            file_count=len(files),
            languages=languages,
            language_stats=language_stats,
            frameworks=frameworks,
        )
