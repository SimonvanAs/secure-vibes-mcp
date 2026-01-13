"""Handler for run_threat_modeling MCP tool."""

from pathlib import Path
from typing import Any

from securevibes_mcp.agents.component_filter import ComponentFilter
from securevibes_mcp.agents.dependency import DependencyValidator
from securevibes_mcp.agents.security_parser import SecurityDocParser
from securevibes_mcp.agents.stride_analyzer import STRIDEAnalyzer
from securevibes_mcp.agents.threat_model_builder import ThreatModelBuilder
from securevibes_mcp.agents.threat_model_output import ThreatModelWriter


class ThreatModelingHandler:
    """Handler for the run_threat_modeling MCP tool.

    Orchestrates the threat modeling workflow:
    1. Validates SECURITY.md dependency
    2. Parses components from SECURITY.md
    3. Applies STRIDE analysis
    4. Builds and stores THREAT_MODEL.json
    """

    def run(
        self,
        project_path: str,
        focus_components: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run threat modeling analysis on a project.

        Args:
            project_path: Path to the project root.
            focus_components: Optional list of component names to analyze.

        Returns:
            Dictionary with analysis results.
        """
        root_path = Path(project_path)

        # Validate SECURITY.md dependency
        validator = DependencyValidator(root_path)
        validation = validator.validate("run_threat_modeling")
        if not validation.satisfied:
            return {
                "status": "error",
                "message": f"Missing required artifact: {', '.join(validation.missing)}. "
                f"Run run_assessment first to generate SECURITY.md.",
            }

        # Parse SECURITY.md
        parser = SecurityDocParser(root_path)
        parsed_doc = parser.parse()
        if parsed_doc is None:
            return {
                "status": "error",
                "message": "Failed to parse SECURITY.md artifact.",
            }

        # Extract components
        components = parsed_doc.extract_components()

        # Apply component filter if specified
        component_filter = ComponentFilter(focus_components=focus_components)
        valid_focus, invalid_focus = component_filter.validate(components)
        filtered_components = component_filter.filter(components)

        # Run STRIDE analysis
        analyzer = STRIDEAnalyzer()
        findings = analyzer.analyze_components(filtered_components)

        # Build threat model
        builder = ThreatModelBuilder(project_path=project_path)
        threat_model = builder.build(findings)

        # Write artifact
        writer = ThreatModelWriter(root_path=root_path)
        writer.write(threat_model)
        artifact_path = writer.get_artifact_path()

        # Build response
        result: dict[str, Any] = {
            "status": "success",
            "threats_identified": len(findings),
            "components_analyzed": len(filtered_components),
            "artifact_path": str(artifact_path),
            "summary": {
                "by_severity": {
                    k: v for k, v in threat_model.summary.items()
                    if k in ["critical", "high", "medium", "low"]
                },
                "by_category": threat_model.summary.get("by_category", {}),
            },
        }

        # Include invalid focus components warning
        if invalid_focus:
            result["invalid_components"] = invalid_focus

        return result
