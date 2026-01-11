# Technology Stack

This document defines the technologies, frameworks, and tools used to build the SecureVibes MCP Server.

## Core Language

### Python 3.11+

- Primary implementation language
- Modern async/await syntax support
- Type hints for improved code quality
- Rich ecosystem for security tooling

## MCP Framework

### MCP Python SDK

- Official Model Context Protocol SDK for Python
- Provides server implementation primitives
- Handles protocol serialization/deserialization
- Manages tool registration and execution

## Async Runtime

### asyncio (Standard Library)

- Built-in Python async support
- Native integration with MCP SDK
- No additional dependencies required
- Well-documented and widely understood

## Testing

### pytest + pytest-asyncio

- **pytest**: Industry-standard Python testing framework
- **pytest-asyncio**: Async test support for coroutines
- **pytest-cov**: Coverage reporting integration

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=securevibes_mcp --cov-report=html
```

## Code Quality

### Ruff

- Ultra-fast Python linter and formatter
- Replaces flake8, isort, and black in a single tool
- Consistent code style enforcement
- Integrated import sorting

```bash
# Check code
ruff check .

# Format code
ruff format .
```

### Type Checking

- Type hints used throughout the codebase
- Enables IDE autocompletion and error detection
- Improves code documentation and maintainability

## Dependency Management

### uv

- Ultra-fast Python package manager
- Project and virtual environment management
- Lockfile support for reproducible builds
- Drop-in replacement for pip/venv workflows

```bash
# Create virtual environment and install dependencies
uv sync

# Add a dependency
uv add <package>

# Run a command in the virtual environment
uv run <command>
```

## Project Structure

```
securevibes_mcp/
├── pyproject.toml          # Project configuration and dependencies
├── uv.lock                  # Dependency lockfile
├── src/
│   └── securevibes_mcp/
│       ├── __init__.py
│       ├── server.py       # MCP server implementation
│       ├── tools/          # MCP tool definitions
│       ├── agents/         # Security agent implementations
│       └── storage/        # Artifact storage layer
└── tests/
    ├── conftest.py         # pytest fixtures
    └── ...
```

## Development Commands

```bash
# Setup
uv sync                           # Install dependencies

# Development
uv run python -m securevibes_mcp  # Run MCP server

# Testing
uv run pytest                     # Run tests
uv run pytest --cov               # Run with coverage

# Code Quality
uv run ruff check .               # Lint code
uv run ruff format .              # Format code
```
