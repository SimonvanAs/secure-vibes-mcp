# Implementation Plan: MCP Server Foundation with Assessment Agent

## Phase 1: Project Setup and Infrastructure [checkpoint: de2692d]

- [x] Task 1.1: Initialize Python project with uv `e8f6c2c`
  - [x] Sub-task: Create pyproject.toml with project metadata and dependencies
  - [x] Sub-task: Add dependencies (mcp, anthropic, pytest, pytest-asyncio, pytest-cov, ruff)
  - [x] Sub-task: Run `uv sync` to create virtual environment and lockfile
  - [x] Sub-task: Verify project structure matches tech-stack.md

- [x] Task 1.2: Create package structure `feef5d8`
  - [x] Sub-task: Write tests for package importability
  - [x] Sub-task: Create `src/securevibes_mcp/__init__.py` with version
  - [x] Sub-task: Create `src/securevibes_mcp/server.py` skeleton
  - [x] Sub-task: Create `src/securevibes_mcp/__main__.py` for CLI entry point

- [x] Task 1.3: Configure development tools `95a4fc6`
  - [x] Sub-task: Add Ruff configuration to pyproject.toml
  - [x] Sub-task: Add pytest configuration to pyproject.toml
  - [x] Sub-task: Create `tests/conftest.py` with shared fixtures
  - [x] Sub-task: Verify `uv run ruff check .` and `uv run pytest` work

- [x] Task: Conductor - User Manual Verification 'Phase 1: Project Setup and Infrastructure' (Protocol in workflow.md)

## Phase 2: MCP Server Core [checkpoint: 4e22bf4]

- [x] Task 2.1: Implement MCP server initialization `80424ea`
  - [x] Sub-task: Write tests for server creation and lifecycle
  - [x] Sub-task: Implement `SecureVibesMCPServer` class with MCP SDK
  - [x] Sub-task: Add async context manager for server lifecycle
  - [x] Sub-task: Implement environment variable configuration loading

- [x] Task 2.2: Implement tool registration framework `d074c29`
  - [x] Sub-task: Write tests for tool listing and schema validation
  - [x] Sub-task: Create tool registry with input/output schema definitions
  - [x] Sub-task: Register all 8 tools with proper JSON schemas
  - [x] Sub-task: Implement tool dispatch mechanism

- [x] Task 2.3: Add placeholder tool implementations `7ea80ba`
  - [x] Sub-task: Write tests for placeholder responses
  - [x] Sub-task: Implement placeholder handlers for unimplemented tools
  - [x] Sub-task: Return structured "not implemented" responses with tool name

- [x] Task: Conductor - User Manual Verification 'Phase 2: MCP Server Core' (Protocol in workflow.md)

## Phase 3: Artifact Storage Layer

- [x] Task 3.1: Implement storage manager `d430943`
  - [x] Sub-task: Write tests for directory creation and file operations
  - [x] Sub-task: Create `ScanStateManager` class
  - [x] Sub-task: Implement `.securevibes/` directory initialization
  - [x] Sub-task: Implement artifact read/write operations

- [ ] Task 3.2: Implement artifact status checking
  - [ ] Sub-task: Write tests for status reporting
  - [ ] Sub-task: Implement `get_status()` method returning all artifact states
  - [ ] Sub-task: Include existence, modification time, and size for each artifact

- [ ] Task 3.3: Implement error handling for storage operations
  - [ ] Sub-task: Write tests for error scenarios (permission denied, disk full, etc.)
  - [ ] Sub-task: Create structured error response format
  - [ ] Sub-task: Handle file system errors gracefully

- [ ] Task: Conductor - User Manual Verification 'Phase 3: Artifact Storage Layer' (Protocol in workflow.md)

## Phase 4: Query Tools Implementation

- [ ] Task 4.1: Implement get_scan_status tool
  - [ ] Sub-task: Write tests for status retrieval with various artifact states
  - [ ] Sub-task: Implement tool handler using ScanStateManager
  - [ ] Sub-task: Return structured response with all artifact metadata

- [ ] Task 4.2: Implement get_artifact tool
  - [ ] Sub-task: Write tests for artifact retrieval (existing and missing)
  - [ ] Sub-task: Implement tool handler with artifact name validation
  - [ ] Sub-task: Return raw artifact content with metadata

- [ ] Task 4.3: Add path validation
  - [ ] Sub-task: Write tests for invalid path handling
  - [ ] Sub-task: Validate target path exists before operations
  - [ ] Sub-task: Return clear error for non-existent paths

- [ ] Task: Conductor - User Manual Verification 'Phase 4: Query Tools Implementation' (Protocol in workflow.md)

## Phase 5: Assessment Agent Implementation

- [ ] Task 5.1: Implement codebase scanning
  - [ ] Sub-task: Write tests for language and framework detection
  - [ ] Sub-task: Create file tree walker respecting .gitignore
  - [ ] Sub-task: Implement language detection from file extensions
  - [ ] Sub-task: Detect common frameworks from manifest files

- [ ] Task 5.2: Implement SECURITY.md generation
  - [ ] Sub-task: Write tests for document generation
  - [ ] Sub-task: Create template for SECURITY.md structure
  - [ ] Sub-task: Generate architecture overview section
  - [ ] Sub-task: Generate security-relevant observations section

- [ ] Task 5.3: Implement run_assessment tool handler
  - [ ] Sub-task: Write integration tests for full assessment flow
  - [ ] Sub-task: Wire up scanning and generation components
  - [ ] Sub-task: Store artifact via ScanStateManager
  - [ ] Sub-task: Return summary with languages, file count, and components

- [ ] Task 5.4: Add dependency validation
  - [ ] Sub-task: Write tests for dependency checking
  - [ ] Sub-task: Implement `DependencyValidator` class
  - [ ] Sub-task: Validate no prerequisites for assessment (entry point)

- [ ] Task: Conductor - User Manual Verification 'Phase 5: Assessment Agent Implementation' (Protocol in workflow.md)

## Phase 6: Integration and Polish

- [ ] Task 6.1: End-to-end integration testing
  - [ ] Sub-task: Write E2E test for complete assessment workflow
  - [ ] Sub-task: Test tool registration and invocation via MCP protocol
  - [ ] Sub-task: Verify artifact persistence across tool calls

- [ ] Task 6.2: Documentation and final checks
  - [ ] Sub-task: Add docstrings to all public APIs
  - [ ] Sub-task: Verify >80% test coverage
  - [ ] Sub-task: Run final Ruff check and format
  - [ ] Sub-task: Update CLAUDE.md with implementation details

- [ ] Task: Conductor - User Manual Verification 'Phase 6: Integration and Polish' (Protocol in workflow.md)
