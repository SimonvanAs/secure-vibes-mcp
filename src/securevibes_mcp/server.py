"""SecureVibes MCP Server implementation."""

import os
from dataclasses import dataclass
from typing import Any, Self

from mcp.server import Server

from securevibes_mcp.tools.registry import Tool, get_tool_registry

VALID_MODELS = {"haiku", "sonnet", "opus"}
DEFAULT_MODEL = "sonnet"


@dataclass
class ServerConfig:
    """Configuration for the SecureVibes MCP Server.

    Attributes:
        model: The Claude model to use for agent execution.
    """

    model: str = DEFAULT_MODEL

    @classmethod
    def from_environment(cls) -> Self:
        """Load configuration from environment variables.

        Returns:
            ServerConfig instance with values from environment.
        """
        model = os.environ.get("SECUREVIBES_MODEL", DEFAULT_MODEL)
        if model not in VALID_MODELS:
            model = DEFAULT_MODEL
        return cls(model=model)


class SecureVibesMCPServer:
    """MCP server for SecureVibes security scanning agents.

    This server exposes security scanning tools via the Model Context Protocol,
    enabling Claude to perform autonomous security analysis through natural
    conversation.
    """

    def __init__(self, name: str = "securevibes") -> None:
        """Initialize the SecureVibes MCP Server.

        Args:
            name: The name of the MCP server.
        """
        self.name = name
        self.server = Server(name)
        self.config = ServerConfig.from_environment()
        self._registry = get_tool_registry()

    async def __aenter__(self) -> Self:
        """Enter async context manager.

        Returns:
            The server instance.
        """
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context manager.

        Args:
            exc_type: Exception type if an exception was raised.
            exc_val: Exception value if an exception was raised.
            exc_tb: Exception traceback if an exception was raised.
        """
        # Cleanup will be added when we implement actual server logic
        pass

    def list_tools(self) -> list[Tool]:
        """List all registered MCP tools.

        Returns:
            List of all registered tools.
        """
        return self._registry.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call a registered tool by name.

        Args:
            name: The name of the tool to call.
            arguments: The arguments to pass to the tool.

        Returns:
            The tool's response.

        Raises:
            ValueError: If the tool is not found or required arguments are missing.
        """
        tool = self._registry.get_tool(name)
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")

        # Validate required arguments
        schema = tool.inputSchema
        required = schema.get("required", [])
        for req_arg in required:
            if req_arg not in arguments:
                raise ValueError(f"Missing required argument: {req_arg}")

        return await tool.handler(**arguments)

    async def run(self) -> None:
        """Run the MCP server."""
        # TODO: Implement server run logic
        pass
