# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecureVibes MCP Server is a Model Context Protocol server that exposes security scanning agents as tools for Claude. It enables conversational security analysis through natural language, allowing developers to scan, analyze, and remediate vulnerabilities through dialogue.

## Architecture

### Layer Structure
1. **Tool Layer (MCP Interface)** - Exposes tools like `run_assessment`, `run_threat_modeling`, `run_code_review`, `run_dast`, `generate_report`, and query tools
2. **Orchestration Layer** - Handles dependency validation, state management, artifact caching, and progress tracking
3. **Agent Execution Layer** - Runs the five specialized security agents (Assessment, Threat Modeling, Code Review, DAST, Report Generator)
4. **Storage Layer** - Manages artifacts in `.securevibes/` directory

### Agent Pipeline & Dependencies
```
assessment → threat-modeling → code-review → dast → report
     ↓              ↓               ↓          ↓         ↓
SECURITY.md → THREAT_MODEL.json → VULNERABILITIES.json → DAST_VALIDATION.json → scan_results.json
                                                                                 scan_report.md
```

Each agent depends on artifacts from the previous stage:
- `assessment`: No dependencies (entry point)
- `threat-modeling`: Requires `SECURITY.md`
- `code-review`: Requires `THREAT_MODEL.json`
- `dast`: Requires `VULNERABILITIES.json`
- `report-generator`: Requires `VULNERABILITIES.json`

### Key Classes
- `SecureVibesMCPServer`: Main MCP server with tool handlers (`src/securevibes_mcp/server.py`)
- `ToolRegistry`: Manages tool registration and dispatch (`src/securevibes_mcp/tools/registry.py`)
- `DependencyValidator`: Validates artifact dependencies before agent execution (`src/securevibes_mcp/agents/dependency.py`)
- `ScanStateManager`: Manages artifact state and caching in `.securevibes/` (`src/securevibes_mcp/storage/manager.py`)
- `CodebaseScanner`: Scans codebase for languages, frameworks, and file structure (`src/securevibes_mcp/agents/scanner.py`)
- `SecurityDocGenerator`: Generates SECURITY.md from scan results (`src/securevibes_mcp/agents/generator.py`)

## MCP Tools

**Core Agent Tools:**
- `run_assessment` - Analyzes codebase architecture, creates `SECURITY.md` **(Implemented)**
- `run_threat_modeling` - STRIDE analysis, creates `THREAT_MODEL.json` **(Implemented)**
- `run_code_review` - Validates threats, creates `VULNERABILITIES.json` **(Implemented)**
- `run_dast` - Dynamic testing against running app, creates `DAST_VALIDATION.json` **(Implemented)**
- `generate_report` - Compiles findings into `scan_results.json` and `scan_report.md` **(Implemented)**

**Query Tools:**
- `get_scan_status` - Returns state of all artifacts **(Implemented)**
- `get_vulnerabilities` - Filtered vulnerability retrieval **(Implemented)**
- `get_artifact` - Raw artifact content access **(Implemented)**

## Build & Run Commands

```bash
# Install dependencies (using uv)
uv sync

# Run the MCP server
uv run python -m securevibes_mcp

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=securevibes_mcp --cov-report=html

# Lint code
uv run ruff check .

# Format code
uv run ruff format .
```

## Configuration

Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "securevibes": {
      "command": "python",
      "args": ["-m", "securevibes_mcp"],
      "env": {
        "ANTHROPIC_API_KEY": "your-api-key"
      }
    }
  }
}
```

**Environment Variables:**
- `ANTHROPIC_API_KEY` - Required for agent execution
- `SECUREVIBES_ASSESSMENT_MODEL` - Model override for assessment (haiku/sonnet/opus)
- `SECUREVIBES_CODE_REVIEW_MODEL` - Model override for code review
- `SECUREVIBES_MAX_TURNS` - Maximum agent turns (default: 75)
- `SECUREVIBES_DEBUG` - Enable debug logging

## Security Constraints

- MCP server has READ access only to user-specified directories
- Writes are restricted to `.securevibes/` subdirectory
- API keys must never be exposed in tool responses
