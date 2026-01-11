"""Tests for package structure and importability."""

import importlib


def test_package_imports():
    """Test that the main package can be imported."""
    import securevibes_mcp

    assert securevibes_mcp is not None


def test_package_has_version():
    """Test that the package has a version attribute."""
    import securevibes_mcp

    assert hasattr(securevibes_mcp, "__version__")
    assert isinstance(securevibes_mcp.__version__, str)
    assert len(securevibes_mcp.__version__) > 0


def test_server_module_imports():
    """Test that the server module can be imported."""
    from securevibes_mcp import server

    assert server is not None


def test_server_has_main_class():
    """Test that the server module has the main server class."""
    from securevibes_mcp.server import SecureVibesMCPServer

    assert SecureVibesMCPServer is not None


def test_main_module_exists():
    """Test that __main__.py exists and can be imported."""
    spec = importlib.util.find_spec("securevibes_mcp.__main__")
    assert spec is not None, "__main__.py module should exist"


def test_main_function_exists():
    """Test that main function exists in __main__ module."""
    from securevibes_mcp.__main__ import main

    assert callable(main)


def test_server_initialization():
    """Test that SecureVibesMCPServer can be instantiated."""
    from securevibes_mcp.server import SecureVibesMCPServer

    server = SecureVibesMCPServer()
    assert server.name == "securevibes"
    assert server.server is not None


def test_server_custom_name():
    """Test that SecureVibesMCPServer accepts custom name."""
    from securevibes_mcp.server import SecureVibesMCPServer

    server = SecureVibesMCPServer(name="custom")
    assert server.name == "custom"
