"""Shared pytest fixtures for SecureVibes MCP tests."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test artifacts.

    Yields:
        Path to the temporary directory.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_project(temp_dir: Path) -> Path:
    """Create a sample project structure for testing.

    Args:
        temp_dir: Temporary directory fixture.

    Returns:
        Path to the sample project root.
    """
    # Create a minimal Python project structure
    (temp_dir / "src").mkdir()
    (temp_dir / "src" / "main.py").write_text('print("Hello")\n')
    (temp_dir / "requirements.txt").write_text("requests>=2.0.0\n")
    (temp_dir / "README.md").write_text("# Sample Project\n")

    return temp_dir


@pytest.fixture
def securevibes_dir(temp_dir: Path) -> Path:
    """Create a .securevibes directory for testing artifact storage.

    Args:
        temp_dir: Temporary directory fixture.

    Returns:
        Path to the .securevibes directory.
    """
    securevibes_path = temp_dir / ".securevibes"
    securevibes_path.mkdir()
    return securevibes_path
