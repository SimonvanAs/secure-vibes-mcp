# Implementation Plan: Code Review Agent

## Phase 1: Threat Model Reader

- [x] Task 1.1: Implement THREAT_MODEL.json parser `6f0511b`
  - [x] Sub-task: Write tests for loading THREAT_MODEL.json artifact
  - [x] Sub-task: Create `ThreatModelReader` class
  - [x] Sub-task: Implement artifact loading via ScanStateManager
  - [x] Sub-task: Parse threat entries into structured objects

- [ ] Task 1.2: Implement threat validation
  - [ ] Sub-task: Write tests for threat entry validation
  - [ ] Sub-task: Validate required fields (id, category, component, severity)
  - [ ] Sub-task: Handle malformed or incomplete threat entries gracefully

- [ ] Task: Conductor - User Manual Verification 'Phase 1: Threat Model Reader' (Protocol in workflow.md)

## Phase 2: Vulnerability Pattern System

- [ ] Task 2.1: Create vulnerability pattern registry
  - [ ] Sub-task: Write tests for pattern registry operations
  - [ ] Sub-task: Define `VulnerabilityPattern` dataclass
  - [ ] Sub-task: Create `PatternRegistry` class with pattern lookup by STRIDE category

- [ ] Task 2.2: Implement STRIDE category patterns
  - [ ] Sub-task: Write tests for pattern matching
  - [ ] Sub-task: Implement Spoofing patterns (auth bypass, weak credentials)
  - [ ] Sub-task: Implement Tampering patterns (SQL injection, command injection, XSS)
  - [ ] Sub-task: Implement Repudiation patterns (missing logging)
  - [ ] Sub-task: Implement InfoDisclosure patterns (hardcoded secrets, data exposure)
  - [ ] Sub-task: Implement DoS patterns (resource exhaustion, regex DoS)
  - [ ] Sub-task: Implement EoP patterns (privilege escalation, missing authz)

- [ ] Task 2.3: Implement CWE mapping
  - [ ] Sub-task: Write tests for CWE lookups
  - [ ] Sub-task: Create CWE ID mapping for each pattern type
  - [ ] Sub-task: Include CWE descriptions in mappings

- [ ] Task: Conductor - User Manual Verification 'Phase 2: Vulnerability Pattern System' (Protocol in workflow.md)

## Phase 3: Code Scanner

- [ ] Task 3.1: Implement file scanner
  - [ ] Sub-task: Write tests for file traversal
  - [ ] Sub-task: Create `CodeScanner` class
  - [ ] Sub-task: Implement recursive file discovery
  - [ ] Sub-task: Filter by file extensions (Python focus)

- [ ] Task 3.2: Implement pattern matching engine
  - [ ] Sub-task: Write tests for pattern detection
  - [ ] Sub-task: Implement regex-based pattern matching
  - [ ] Sub-task: Extract line numbers and code snippets for matches
  - [ ] Sub-task: Associate matches with threat IDs

- [ ] Task 3.3: Implement component-based filtering
  - [ ] Sub-task: Write tests for component filtering
  - [ ] Sub-task: Support `focus_components` parameter
  - [ ] Sub-task: Map components to relevant code paths
  - [ ] Sub-task: Validate component names against SECURITY.md

- [ ] Task: Conductor - User Manual Verification 'Phase 3: Code Scanner' (Protocol in workflow.md)

## Phase 4: Vulnerability Output Generator

- [ ] Task 4.1: Implement vulnerability builder
  - [ ] Sub-task: Write tests for vulnerability structure
  - [ ] Sub-task: Create `Vulnerability` dataclass with required fields
  - [ ] Sub-task: Create `VulnerabilityBuilder` class
  - [ ] Sub-task: Generate unique vulnerability IDs (VULN-NNN)

- [ ] Task 4.2: Implement threat status tracking
  - [ ] Sub-task: Write tests for status assignment
  - [ ] Sub-task: Mark threats as "confirmed" when code evidence found
  - [ ] Sub-task: Mark threats as "not_confirmed" when no evidence found
  - [ ] Sub-task: Include all threats in output regardless of status

- [ ] Task 4.3: Implement VULNERABILITIES.json output
  - [ ] Sub-task: Write tests for JSON serialization
  - [ ] Sub-task: Create `VulnerabilitySerializer` class
  - [ ] Sub-task: Implement summary statistics generation
  - [ ] Sub-task: Write artifact via ScanStateManager

- [ ] Task: Conductor - User Manual Verification 'Phase 4: Vulnerability Output Generator' (Protocol in workflow.md)

## Phase 5: Tool Handler Integration

- [ ] Task 5.1: Implement run_code_review handler
  - [ ] Sub-task: Write integration tests for full workflow
  - [ ] Sub-task: Create `CodeReviewHandler` class
  - [ ] Sub-task: Wire up reader, scanner, and output components
  - [ ] Sub-task: Validate THREAT_MODEL.json dependency

- [ ] Task 5.2: Update tool registry
  - [ ] Sub-task: Write tests for tool dispatch
  - [ ] Sub-task: Replace placeholder with real handler
  - [ ] Sub-task: Verify tool schema matches implementation

- [ ] Task 5.3: End-to-end testing
  - [ ] Sub-task: Write E2E test for complete code review workflow
  - [ ] Sub-task: Test assessment -> threat modeling -> code review pipeline
  - [ ] Sub-task: Verify artifact persistence and retrieval

- [ ] Task: Conductor - User Manual Verification 'Phase 5: Tool Handler Integration' (Protocol in workflow.md)
