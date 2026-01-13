"""Handler for run_code_review MCP tool."""

from pathlib import Path
from typing import Any

from securevibes_mcp.agents.dependency import DependencyValidator
from securevibes_mcp.agents.threat_model_reader import ThreatModelReader
from securevibes_mcp.agents.vulnerability_builder import (
    VulnerabilityBuilder,
    VulnerabilityOutput,
    VulnerabilityWriter,
)
from securevibes_mcp.agents.vulnerability_scanner import VulnerabilityScanner


class CodeReviewHandler:
    """Handler for the run_code_review MCP tool.

    Orchestrates the code review workflow:
    1. Validates THREAT_MODEL.json dependency
    2. Reads threats from threat model
    3. Scans code for vulnerability patterns
    4. Maps matches to threats by STRIDE category
    5. Builds and stores VULNERABILITIES.json
    """

    def run(
        self,
        project_path: str,
        focus_components: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run code review analysis on a project.

        Args:
            project_path: Path to the project root.
            focus_components: Optional list of component paths to focus on.

        Returns:
            Dictionary with analysis results.
        """
        root_path = Path(project_path)

        # Validate THREAT_MODEL.json dependency
        validator = DependencyValidator(root_path)
        validation = validator.validate("run_code_review")
        if not validation.satisfied:
            return {
                "status": "error",
                "message": f"Missing required artifact: {', '.join(validation.missing)}. "
                f"Run run_threat_modeling first to generate THREAT_MODEL.json.",
            }

        # Read threat model
        reader = ThreatModelReader(root_path)
        threat_data = reader.read()
        if threat_data is None:
            return {
                "status": "error",
                "message": "Failed to parse THREAT_MODEL.json artifact.",
            }

        # Validate threat entries
        validation_errors = reader.get_validation_errors()
        if validation_errors:
            error_msgs = [
                f"Threat {e.threat_index}: {e.message}" for e in validation_errors
            ]
            return {
                "status": "error",
                "message": f"Invalid threat entries: {'; '.join(error_msgs)}",
            }

        # Get threats and their categories
        threats = threat_data.get("threats", [])
        if not threats:
            return {
                "status": "error",
                "message": "No threats found in THREAT_MODEL.json.",
            }

        # Build category to threat mapping
        category_threats: dict[str, list[dict[str, Any]]] = {}
        for threat in threats:
            category = threat.get("category", "Unknown")
            if category not in category_threats:
                category_threats[category] = []
            category_threats[category].append(threat)

        # Scan code for vulnerability patterns
        scanner = VulnerabilityScanner(root_path=root_path)
        all_matches = scanner.scan_for_patterns(component_paths=focus_components)

        # Build vulnerabilities from matches
        builder = VulnerabilityBuilder()

        # Map matches to threats by category
        for match in all_matches:
            category = match.category
            if category in category_threats:
                # Associate match with first threat in that category
                threat = category_threats[category][0]
                builder.from_match(match, threat_id=threat["id"])

        # Build final output including not_confirmed threats
        vulnerabilities = builder.build_all(threats)

        # Create output
        output = VulnerabilityOutput(vulnerabilities=vulnerabilities)

        # Write artifact
        writer = VulnerabilityWriter(root_path=root_path)
        writer.write(output)
        artifact_path = writer.get_artifact_path()

        # Build response
        summary = output.get_summary()
        result: dict[str, Any] = {
            "status": "success",
            "vulnerabilities_found": summary["confirmed"],
            "threats_analyzed": summary["total_threats"],
            "not_confirmed": summary["not_confirmed"],
            "artifact_path": str(artifact_path),
            "summary": {
                "by_severity": summary["by_severity"],
                "by_cwe": summary["by_cwe"],
            },
        }

        # Include component filter info
        if focus_components:
            result["focus_components"] = focus_components

        return result
