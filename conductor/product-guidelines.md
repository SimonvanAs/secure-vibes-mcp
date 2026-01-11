# Product Guidelines

This document defines the communication style, user experience principles, and operational guidelines for the SecureVibes MCP Server.

## Communication Style

### Tone: Technical and Precise

- Use standard security terminology (CVE, CWE, CVSS, STRIDE, etc.) without simplification
- Reference vulnerability identifiers directly (e.g., "CWE-89: SQL Injection")
- Assume users understand security concepts and industry practices
- Provide actionable, specific information rather than general guidance
- Include code snippets, file paths, and line numbers in findings

### Example Output Style

```
Vulnerability: SQL Injection (CWE-89)
Severity: Critical (CVSS 9.8)
Location: src/auth/login.py:45
Code: cursor.execute(f"SELECT * FROM users WHERE username='{username}'")
Recommendation: Use parameterized queries with placeholders
```

## Vulnerability Presentation

### Flexible Ranking System

Findings support two ranking modes, selectable by the user:

1. **Severity-First** (default) - Orders findings Critical → High → Medium → Low, with CVSS scores where applicable. Aligns with industry-standard triage workflows.

2. **Exploitability-First** - Prioritizes findings confirmed exploitable via DAST, followed by unconfirmed findings. Focuses attention on real, actionable risks.

### Finding Structure

Each vulnerability finding must include:
- Unique identifier
- Title and description
- Severity level and CVSS score (where applicable)
- CWE classification
- File path and line number
- Relevant code snippet
- Remediation recommendation
- DAST validation status (if applicable)

## Operational Behavior

### Asynchronous Execution Model

Long-running operations (full scans, multi-file analysis) use an async pattern:

1. Tool call returns immediately with a job ID
2. `get_scan_status` tool allows polling for progress
3. Results are available via `get_artifact` or `get_vulnerabilities` once complete

This allows Claude to manage multiple operations and provide updates without blocking.

### Artifact Storage

All scan artifacts are stored in a `.securevibes/` directory within the scanned project:

```
project/
├── .securevibes/
│   ├── SECURITY.md
│   ├── THREAT_MODEL.json
│   ├── VULNERABILITIES.json
│   ├── DAST_VALIDATION.json
│   └── scan_results.json
└── src/
    └── ...
```

Benefits:
- Artifacts are version-controllable with the codebase
- Scan history persists across sessions
- Easy to review and share findings

### Model Configuration

Model selection is configured globally via environment variable:

```bash
export SECUREVIBES_MODEL=sonnet  # Options: haiku, sonnet, opus
```

This setting applies to all agent executions, providing predictable costs and simple configuration.

## Error Handling

### Error Response Format

Errors should be structured and actionable:

```json
{
  "error": true,
  "code": "DEPENDENCY_MISSING",
  "message": "THREAT_MODEL.json required for code review",
  "suggestion": "Run run_threat_modeling first"
}
```

### Dependency Validation

Before executing any agent, validate that required artifacts exist. Provide clear error messages indicating which prerequisite agent must run first.
