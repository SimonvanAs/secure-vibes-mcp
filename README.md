# SecureVibes MCP

A Model Context Protocol server that provides AI-powered security scanning through conversational analysis. Scan codebases for vulnerabilities using natural language with Claude.

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/securevibes_mcp.git
cd securevibes_mcp

# Install with uv
uv sync
```

## Configuration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "securevibes": {
      "command": "uv",
      "args": ["run", "python", "-m", "securevibes_mcp"],
      "cwd": "/path/to/securevibes_mcp"
    }
  }
}
```

## Security Pipeline

SecureVibes uses a sequential pipeline where each stage builds on the previous:

```
run_assessment → run_threat_modeling → run_code_review → run_dast → generate_report
      ↓                  ↓                   ↓               ↓              ↓
 SECURITY.md    THREAT_MODEL.json   VULNERABILITIES.json  DAST_*.json  scan_results.json
                                                                       scan_report.md
```

## Usage

### 1. Run Assessment

Analyzes your codebase and creates a security baseline document.

```
"Run a security assessment on /path/to/my/project"
```

Creates: `.securevibes/SECURITY.md`

### 2. Run Threat Modeling

Performs STRIDE analysis based on the security document.

```
"Run threat modeling on /path/to/my/project"
```

Creates: `.securevibes/THREAT_MODEL.json`

Options:
- `focus_components`: Analyze specific components only

### 3. Run Code Review

Scans code for vulnerability patterns matching identified threats.

```
"Run code review on /path/to/my/project"
```

Creates: `.securevibes/VULNERABILITIES.json`

Options:
- `focus_components`: Scan specific paths only (e.g., `["auth", "api"]`)

### 4. Run DAST

Tests confirmed vulnerabilities against a running application.

```
"Run DAST on /path/to/my/project targeting http://localhost:8080"
```

Creates: `.securevibes/DAST_VALIDATION.json`

Options:
- `target_url`: Base URL of the running application (required)
- `vulnerability_ids`: Test specific vulnerabilities only

### 5. Generate Report

Compiles all findings into comprehensive reports.

```
"Generate a security report for /path/to/my/project"
```

Creates: `.securevibes/scan_results.json` and `.securevibes/scan_report.md`

Options:
- `format`: Output format - `json`, `markdown`, or `both` (default)

### 6. Check Status

View the state of all security artifacts:

```
"What's the scan status for /path/to/my/project"
```

### 7. Get Artifact

Retrieve any artifact content:

```
"Show me the THREAT_MODEL.json for /path/to/my/project"
```

## Example Conversation

```
User: Run a security assessment on /Users/me/myapp

Claude: I've completed the security assessment. Found 45 files across
Python and JavaScript. Detected Flask and React frameworks.

User: Now do threat modeling

Claude: Identified 12 threats across STRIDE categories:
- 3 critical (authentication, SQL injection, privilege escalation)
- 5 high (XSS, session management, data exposure)
- 4 medium (logging, DoS, input validation)

User: Run code review focusing on the auth module

Claude: Found 5 confirmed vulnerabilities in the auth module:
- VULN-001: Hardcoded credentials in config.py:23
- VULN-002: SQL injection in user_lookup.py:45
...
```

## Artifacts

All artifacts are stored in `.securevibes/` within your project:

| Artifact | Description |
|----------|-------------|
| `SECURITY.md` | Architecture overview, components, data flows |
| `THREAT_MODEL.json` | STRIDE threats with severity and CVSS ranges |
| `VULNERABILITIES.json` | Code findings with file locations and CWE IDs |
| `DAST_VALIDATION.json` | Exploitability test results from dynamic testing |
| `scan_results.json` | Comprehensive JSON report with all findings |
| `scan_report.md` | Human-readable Markdown security report |

## Development

```bash
# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=securevibes_mcp

# Lint
uv run ruff check .

# Format
uv run ruff format .
```

## License

MIT
