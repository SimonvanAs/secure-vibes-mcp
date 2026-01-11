"""Tests for MCP server initialization and lifecycle."""

import os
from unittest.mock import patch

import pytest

from securevibes_mcp.server import SecureVibesMCPServer


class TestServerInitialization:
    """Tests for server initialization."""

    def test_server_creates_mcp_server(self):
        """Test that server creates an MCP Server instance."""
        server = SecureVibesMCPServer()
        assert server.server is not None
        assert server.name == "securevibes"

    def test_server_accepts_custom_name(self):
        """Test that server accepts a custom name."""
        server = SecureVibesMCPServer(name="custom-server")
        assert server.name == "custom-server"

    def test_server_has_config(self):
        """Test that server has configuration object."""
        server = SecureVibesMCPServer()
        assert hasattr(server, "config")
        assert server.config is not None


class TestServerConfiguration:
    """Tests for server configuration loading."""

    def test_default_model_configuration(self):
        """Test default model is sonnet when env var not set."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove SECUREVIBES_MODEL if it exists
            os.environ.pop("SECUREVIBES_MODEL", None)
            server = SecureVibesMCPServer()
            assert server.config.model == "sonnet"

    def test_model_from_environment(self):
        """Test model can be configured via environment variable."""
        with patch.dict(os.environ, {"SECUREVIBES_MODEL": "opus"}):
            server = SecureVibesMCPServer()
            assert server.config.model == "opus"

    def test_invalid_model_defaults_to_sonnet(self):
        """Test invalid model value defaults to sonnet."""
        with patch.dict(os.environ, {"SECUREVIBES_MODEL": "invalid"}):
            server = SecureVibesMCPServer()
            assert server.config.model == "sonnet"


class TestServerLifecycle:
    """Tests for server async lifecycle."""

    @pytest.mark.asyncio
    async def test_server_run_is_async(self):
        """Test that server.run() is an async method."""
        server = SecureVibesMCPServer()
        # Should be awaitable without error (even if it does nothing yet)
        import inspect

        assert inspect.iscoroutinefunction(server.run)

    @pytest.mark.asyncio
    async def test_server_context_manager(self):
        """Test server can be used as async context manager."""
        async with SecureVibesMCPServer() as server:
            assert server is not None
            assert server.name == "securevibes"
