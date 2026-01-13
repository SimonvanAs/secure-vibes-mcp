# Implementation Plan: Code Review Agent

## Phase 1: Threat Model Reader

- [x] Task 1.1: Implement THREAT_MODEL.json parser `6f0511b`
  - [x] Sub-task: Write tests for loading THREAT_MODEL.json artifact
  - [x] Sub-task: Create `ThreatModelReader` class
  - [x] Sub-task: Implement artifact loading via ScanStateManager
  - [x] Sub-task: Parse threat entries into structured objects

- [x] Task 1.2: Implement threat validation `c193c20`
  - [x] Sub-task: Write tests for threat entry validation
  - [x] Sub-task: Validate required fields (id, category, component, severity)
  - [x] Sub-task: Handle malformed or incomplete threat entries gracefully

- [ ] Task: Conductor - User Manual Verification 'Phase 1: Threat Model Reader' (Protocol in workflow.md)

## Phase 2: Vulnerability Pattern System

- [x] Task 2.1: Create vulnerability pattern registry `6fe4b35`
  - [x] Sub-task: Write tests for pattern registry operations
  - [x] Sub-task: Define `VulnerabilityPattern` dataclass
  - [x] Sub-task: Create `PatternRegistry` class with pattern lookup by STRIDE category

- [x] Task 2.2: Implement STRIDE category patterns `6fe4b35`
  - [x] Sub-task: Write tests for pattern matching
  - [x] Sub-task: Implement Spoofing patterns (auth bypass, weak credentials)
  - [x] Sub-task: Implement Tampering patterns (SQL injection, command injection, XSS)
  - [x] Sub-task: Implement Repudiation patterns (missing logging)
  - [x] Sub-task: Implement InfoDisclosure patterns (hardcoded secrets, data exposure)
  - [x] Sub-task: Implement DoS patterns (resource exhaustion, regex DoS)
  - [x] Sub-task: Implement EoP patterns (privilege escalation, missing authz)

- [x] Task 2.3: Implement CWE mapping `6fe4b35`
  - [x] Sub-task: Write tests for CWE lookups
  - [x] Sub-task: Create CWE ID mapping for each pattern type
  - [x] Sub-task: Include CWE descriptions in mappings

- [ ] Task: Conductor - User Manual Verification 'Phase 2: Vulnerability Pattern System' (Protocol in workflow.md)

## Phase 3: Code Scanner

- [x] Task 3.1: Implement file scanner `8eb54f5`
  - [x] Sub-task: Write tests for file traversal
  - [x] Sub-task: Create `VulnerabilityScanner` class
  - [x] Sub-task: Implement recursive file discovery
  - [x] Sub-task: Filter by file extensions (Python focus)

- [x] Task 3.2: Implement pattern matching engine `8eb54f5`
  - [x] Sub-task: Write tests for pattern detection
  - [x] Sub-task: Implement regex-based pattern matching
  - [x] Sub-task: Extract line numbers and code snippets for matches
  - [x] Sub-task: Associate matches with threat IDs

- [x] Task 3.3: Implement component-based filtering `7fa57a7`
  - [x] Sub-task: Write tests for component filtering
  - [x] Sub-task: Support `component_paths` parameter
  - [x] Sub-task: Map components to relevant code paths
  - [x] Sub-task: Filter files by component path patterns

- [ ] Task: Conductor - User Manual Verification 'Phase 3: Code Scanner' (Protocol in workflow.md)

## Phase 4: Vulnerability Output Generator

- [x] Task 4.1: Implement vulnerability builder `31a0438`
  - [x] Sub-task: Write tests for vulnerability structure
  - [x] Sub-task: Create `Vulnerability` dataclass with required fields
  - [x] Sub-task: Create `VulnerabilityBuilder` class
  - [x] Sub-task: Generate unique vulnerability IDs (VULN-NNN)

- [x] Task 4.2: Implement threat status tracking `31a0438`
  - [x] Sub-task: Write tests for status assignment
  - [x] Sub-task: Mark threats as "confirmed" when code evidence found
  - [x] Sub-task: Mark threats as "not_confirmed" when no evidence found
  - [x] Sub-task: Include all threats in output regardless of status

- [x] Task 4.3: Implement VULNERABILITIES.json output `31a0438`
  - [x] Sub-task: Write tests for JSON serialization
  - [x] Sub-task: Create `VulnerabilityOutput` class
  - [x] Sub-task: Implement summary statistics generation
  - [x] Sub-task: to_json() and to_dict() methods

- [ ] Task: Conductor - User Manual Verification 'Phase 4: Vulnerability Output Generator' (Protocol in workflow.md)

## Phase 5: Tool Handler Integration

- [x] Task 5.1: Implement run_code_review handler `10700ec`
  - [x] Sub-task: Write integration tests for full workflow
  - [x] Sub-task: Create `CodeReviewHandler` class
  - [x] Sub-task: Wire up reader, scanner, and output components
  - [x] Sub-task: Validate THREAT_MODEL.json dependency

- [x] Task 5.2: Update tool registry `10700ec`
  - [x] Sub-task: Update tests for tool dispatch
  - [x] Sub-task: Replace placeholder with real handler
  - [x] Sub-task: Update tool schema to match implementation

- [x] Task 5.3: End-to-end testing `10700ec`
  - [x] Sub-task: Handler tests cover full code review workflow
  - [x] Sub-task: Tests verify artifact creation and content
  - [x] Sub-task: All 349 tests passing

- [ ] Task: Conductor - User Manual Verification 'Phase 5: Tool Handler Integration' (Protocol in workflow.md)
