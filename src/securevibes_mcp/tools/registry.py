"""Tool registry for SecureVibes MCP tools."""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from securevibes_mcp.tools.handlers import (
    generate_report,
    get_artifact,
    get_scan_status,
    get_vulnerabilities,
    list_suppressions,
    remove_suppression,
    run_assessment,
    run_code_review,
    run_dast,
    run_threat_modeling,
    suppress_vulnerability,
)


@dataclass
class Tool:
    """Definition of an MCP tool.

    Attributes:
        name: The tool name.
        description: Human-readable description of the tool.
        inputSchema: JSON Schema for the tool's input parameters.
        handler: Async function that handles tool calls.
    """

    name: str
    description: str
    inputSchema: dict[str, Any]
    handler: Callable[..., Coroutine[Any, Any, dict[str, Any]]]


@dataclass
class ToolRegistry:
    """Registry of available MCP tools.

    Attributes:
        tools: Dictionary mapping tool names to Tool objects.
    """

    tools: dict[str, Tool] = field(default_factory=dict)

    def register(self, tool: Tool) -> None:
        """Register a tool in the registry.

        Args:
            tool: The tool to register.
        """
        self.tools[tool.name] = tool

    def list_tools(self) -> list[Tool]:
        """List all registered tools.

        Returns:
            List of all registered tools.
        """
        return list(self.tools.values())

    def get_tool(self, name: str) -> Tool | None:
        """Get a tool by name.

        Args:
            name: The name of the tool.

        Returns:
            The tool if found, None otherwise.
        """
        return self.tools.get(name)


# Tool schemas
ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase to scan",
        },
        "model": {
            "type": "string",
            "enum": ["haiku", "sonnet", "opus"],
            "default": "sonnet",
            "description": "Claude model to use for analysis",
        },
        "force": {
            "type": "boolean",
            "default": False,
            "description": "Overwrite existing SECURITY.md if present",
        },
    },
    "required": ["path"],
}

THREAT_MODELING_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "model": {
            "type": "string",
            "enum": ["haiku", "sonnet", "opus"],
            "default": "sonnet",
        },
        "focus_components": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Specific components to analyze",
        },
    },
    "required": ["path"],
}

CODE_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "focus_components": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Component paths to focus analysis on (e.g., ['auth', 'api'])",
        },
    },
    "required": ["path"],
}

DAST_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "target_url": {
            "type": "string",
            "description": "Base URL of running application",
        },
        "model": {
            "type": "string",
            "enum": ["haiku", "sonnet", "opus"],
            "default": "sonnet",
        },
        "vulnerability_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Specific vulnerability IDs to test",
        },
    },
    "required": ["path", "target_url"],
}

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "model": {
            "type": "string",
            "enum": ["haiku", "sonnet", "opus"],
            "default": "sonnet",
        },
        "format": {
            "type": "string",
            "enum": ["json", "markdown", "both"],
            "default": "both",
        },
    },
    "required": ["path"],
}

SCAN_STATUS_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
    },
    "required": ["path"],
}

GET_ARTIFACT_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "artifact_name": {
            "type": "string",
            "enum": [
                "SECURITY.md",
                "THREAT_MODEL.json",
                "VULNERABILITIES.json",
                "SUPPRESSIONS.json",
                "DAST_VALIDATION.json",
                "scan_results.json",
                "scan_report.md",
            ],
            "description": "Name of the artifact to retrieve",
        },
    },
    "required": ["path", "artifact_name"],
}

GET_VULNERABILITIES_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
            "description": "Filter by minimum severity",
        },
        "cwe_id": {
            "type": "string",
            "description": "Filter by specific CWE",
        },
        "file_path": {
            "type": "string",
            "description": "Filter by file path pattern",
        },
        "include_suppressed": {
            "type": "boolean",
            "default": False,
            "description": "Include suppressed vulnerabilities in results",
        },
        "limit": {
            "type": "integer",
            "default": 10,
            "description": "Maximum number of results",
        },
    },
    "required": ["path"],
}

SUPPRESS_VULNERABILITY_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "vuln_id": {
            "type": "string",
            "description": "Vulnerability ID to suppress (e.g., 'VULN-001')",
        },
        "file_pattern": {
            "type": "string",
            "description": "File path pattern to suppress (substring match)",
        },
        "cwe_id": {
            "type": "string",
            "description": "CWE ID to suppress all matching vulnerabilities",
        },
        "reason": {
            "type": "string",
            "enum": ["false_positive", "acceptable_risk", "will_not_fix", "mitigated"],
            "default": "false_positive",
            "description": "Reason for suppression",
        },
        "justification": {
            "type": "string",
            "description": "Detailed justification for the suppression",
        },
    },
    "required": ["path"],
}

REMOVE_SUPPRESSION_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "suppression_id": {
            "type": "string",
            "description": "Suppression ID to remove (e.g., 'SUPP-001')",
        },
    },
    "required": ["path", "suppression_id"],
}

LIST_SUPPRESSIONS_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to codebase",
        },
        "include_expired": {
            "type": "boolean",
            "default": False,
            "description": "Include expired suppressions",
        },
    },
    "required": ["path"],
}


def get_tool_registry() -> ToolRegistry:
    """Create and return a configured tool registry.

    Returns:
        ToolRegistry with all SecureVibes tools registered.
    """
    registry = ToolRegistry()

    # Placeholder handler for unimplemented tools
    async def not_implemented(tool_name: str, **_kwargs: Any) -> dict[str, Any]:
        return {
            "error": True,
            "code": "NOT_IMPLEMENTED",
            "message": f"Tool '{tool_name}' is not yet implemented",
            "tool": tool_name,
        }

    # Register agent tools
    registry.register(
        Tool(
            name="run_assessment",
            description="Analyzes codebase architecture and creates security baseline",
            inputSchema=ASSESSMENT_SCHEMA,
            handler=run_assessment,
        )
    )

    registry.register(
        Tool(
            name="run_threat_modeling",
            description="Performs STRIDE threat analysis on documented architecture",
            inputSchema=THREAT_MODELING_SCHEMA,
            handler=run_threat_modeling,
        )
    )

    registry.register(
        Tool(
            name="run_code_review",
            description="Validates threats through code analysis and identifies vulnerabilities",
            inputSchema=CODE_REVIEW_SCHEMA,
            handler=run_code_review,
        )
    )

    registry.register(
        Tool(
            name="run_dast",
            description="Dynamically tests vulnerabilities via HTTP to confirm exploitability",
            inputSchema=DAST_SCHEMA,
            handler=run_dast,
        )
    )

    registry.register(
        Tool(
            name="generate_report",
            description="Compiles all findings into structured JSON and Markdown reports",
            inputSchema=REPORT_SCHEMA,
            handler=generate_report,
        )
    )

    # Register query tools
    registry.register(
        Tool(
            name="get_scan_status",
            description="Retrieves current state of security artifacts",
            inputSchema=SCAN_STATUS_SCHEMA,
            handler=get_scan_status,
        )
    )

    registry.register(
        Tool(
            name="get_artifact",
            description="Retrieves raw artifact content",
            inputSchema=GET_ARTIFACT_SCHEMA,
            handler=get_artifact,
        )
    )

    registry.register(
        Tool(
            name="get_vulnerabilities",
            description="Retrieves filtered vulnerability data",
            inputSchema=GET_VULNERABILITIES_SCHEMA,
            handler=get_vulnerabilities,
        )
    )

    # Register suppression tools
    registry.register(
        Tool(
            name="suppress_vulnerability",
            description="Suppresses a vulnerability or pattern as false positive or accepted risk",
            inputSchema=SUPPRESS_VULNERABILITY_SCHEMA,
            handler=suppress_vulnerability,
        )
    )

    registry.register(
        Tool(
            name="remove_suppression",
            description="Removes a suppression by ID",
            inputSchema=REMOVE_SUPPRESSION_SCHEMA,
            handler=remove_suppression,
        )
    )

    registry.register(
        Tool(
            name="list_suppressions",
            description="Lists all suppressions for a project",
            inputSchema=LIST_SUPPRESSIONS_SCHEMA,
            handler=list_suppressions,
        )
    )

    return registry
