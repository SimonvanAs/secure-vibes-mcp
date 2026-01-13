"""STRIDE threat analyzer."""

from dataclasses import dataclass
from typing import Any

from securevibes_mcp.agents.security_parser import Component
from securevibes_mcp.agents.threat_templates import ThreatTemplateRegistry


@dataclass
class ThreatFinding:
    """A specific threat finding for a component.

    Attributes:
        category: STRIDE category.
        component: Name of the affected component.
        description: Description of the threat.
        attack_vector: How the threat could be exploited.
        impact: Potential business/security impact.
        severity: Severity level (critical, high, medium, low).
    """

    category: str
    component: str
    description: str
    attack_vector: str
    impact: str
    severity: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all threat finding fields.
        """
        return {
            "category": self.category,
            "component": self.component,
            "description": self.description,
            "attack_vector": self.attack_vector,
            "impact": self.impact,
            "severity": self.severity,
        }


class STRIDEAnalyzer:
    """Analyzer that applies STRIDE threat modeling to components.

    Uses threat templates to identify potential security threats
    for each component based on its type.
    """

    def __init__(self) -> None:
        """Initialize the analyzer with threat template registry."""
        self.registry = ThreatTemplateRegistry()

    def analyze_component(self, component: Component) -> list[ThreatFinding]:
        """Analyze a single component for STRIDE threats.

        Args:
            component: The component to analyze.

        Returns:
            List of ThreatFinding objects for the component.
        """
        templates = self.registry.get_templates_for_type(component.component_type)
        findings: list[ThreatFinding] = []

        for template in templates:
            finding = ThreatFinding(
                category=template.category,
                component=component.name,
                description=template.description,
                attack_vector=template.attack_vector,
                impact=template.impact,
                severity=template.severity,
            )
            findings.append(finding)

        return findings

    def analyze_components(self, components: list[Component]) -> list[ThreatFinding]:
        """Analyze multiple components for STRIDE threats.

        Args:
            components: List of components to analyze.

        Returns:
            Combined list of ThreatFinding objects for all components.
        """
        all_findings: list[ThreatFinding] = []

        for component in components:
            findings = self.analyze_component(component)
            all_findings.extend(findings)

        return all_findings
