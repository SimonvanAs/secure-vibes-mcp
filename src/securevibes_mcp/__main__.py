"""CLI entry point for SecureVibes MCP Server."""

import asyncio

from securevibes_mcp.server import SecureVibesMCPServer


def main() -> None:
    """Run the SecureVibes MCP Server."""
    server = SecureVibesMCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
