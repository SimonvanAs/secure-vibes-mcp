# Specification: MCP Server Foundation with Assessment Agent

## Overview

This track establishes the foundational infrastructure for the SecureVibes MCP Server. It delivers a working MCP server that can be registered with Claude Code, implements the Assessment Agent as the first functional security agent, provides query tools for inspecting scan state, and creates the artifact storage layer.

## Functional Requirements

### FR-1: MCP Server Infrastructure

- **FR-1.1:** Create a Python package `securevibes_mcp` using the MCP Python SDK
- **FR-1.2:** Implement server initialization with proper async lifecycle management
- **FR-1.3:** Register all 8 MCP tools (5 agent tools + 3 query tools) with proper schemas
- **FR-1.4:** Support configuration via environment variables (`SECUREVIBES_MODEL`, `ANTHROPIC_API_KEY`)

### FR-2: Tool Registration

Register the following tools with input/output schemas:

**Agent Tools (placeholder implementations except Assessment):**
- `run_assessment` - Functional implementation
- `run_threat_modeling` - Placeholder returning "not implemented"
- `run_code_review` - Placeholder returning "not implemented"
- `run_dast` - Placeholder returning "not implemented"
- `generate_report` - Placeholder returning "not implemented"

**Query Tools (functional implementations):**
- `get_scan_status` - Returns state of all artifacts
- `get_artifact` - Retrieves raw artifact content
- `get_vulnerabilities` - Placeholder returning "not implemented"

### FR-3: Assessment Agent

- **FR-3.1:** Accept a `path` parameter specifying the codebase to analyze
- **FR-3.2:** Scan the codebase to identify languages, frameworks, and key components
- **FR-3.3:** Generate a `SECURITY.md` document with architecture overview and security-relevant observations
- **FR-3.4:** Store the artifact in `.securevibes/SECURITY.md` within the target project
- **FR-3.5:** Return a summary including languages detected, files analyzed, and key components

### FR-4: Artifact Storage Layer

- **FR-4.1:** Create `.securevibes/` directory in target project if it doesn't exist
- **FR-4.2:** Implement read/write operations for all artifact types
- **FR-4.3:** Support checking artifact existence and modification times
- **FR-4.4:** Handle file system errors gracefully with structured error responses

### FR-5: Query Tools

- **FR-5.1:** `get_scan_status` returns existence and metadata for all artifacts
- **FR-5.2:** `get_artifact` returns raw content of a specified artifact
- **FR-5.3:** Both tools validate that the target path exists

## Non-Functional Requirements

### NFR-1: Code Quality
- >80% test coverage for all modules
- Type hints on all public functions
- Docstrings on all public modules, classes, and functions
- Pass Ruff linting and formatting checks

### NFR-2: Error Handling
- All errors return structured JSON responses
- Dependency validation before agent execution
- Clear error messages with suggested actions

### NFR-3: Performance
- Server startup in <2 seconds
- Tool registration completes synchronously during startup

## Acceptance Criteria

1. MCP server starts successfully and can be registered with Claude Code CLI
2. `run_assessment` successfully analyzes a sample codebase and creates `SECURITY.md`
3. `get_scan_status` correctly reports artifact states
4. `get_artifact` retrieves stored artifacts
5. All tests pass with >80% coverage
6. Code passes Ruff linting and formatting checks

## Out of Scope

- Threat Modeling Agent implementation
- Code Review Agent implementation
- DAST Agent implementation
- Report Generator implementation
- `get_vulnerabilities` filtering logic
- Async job polling (tools will block until complete for MVP)
- CI/CD integration
