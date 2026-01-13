"""Parser for SECURITY.md artifacts."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from securevibes_mcp.storage import ScanStateManager


@dataclass
class Component:
    """A component extracted from the security document.

    Attributes:
        name: The component name.
        component_type: Type of component (api, data_store, authentication, external_integration, service).
        description: Description of the component.
    """

    name: str
    component_type: str
    description: str


@dataclass
class DataFlow:
    """A data flow between components.

    Attributes:
        source: The source component name or type.
        target: The target component name or type.
        description: Description of the data flow.
    """

    source: str
    target: str
    description: str


# Keywords for identifying component types
COMPONENT_TYPE_KEYWORDS: dict[str, list[str]] = {
    "api": ["api", "rest", "endpoint", "graphql", "grpc"],
    "data_store": ["database", "db", "postgres", "mysql", "mongodb", "redis", "cache", "storage"],
    "authentication": ["auth", "jwt", "oauth", "login", "session", "token"],
    "external_integration": ["stripe", "payment", "sendgrid", "email", "twilio", "aws", "s3", "gateway"],
    "service": ["service", "worker", "queue", "scheduler"],
}


@dataclass
class ParsedSecurityDoc:
    """Parsed representation of a SECURITY.md document.

    Attributes:
        raw_content: The raw markdown content.
        sections: Dictionary mapping section names to content.
        languages: List of detected programming languages.
        frameworks: List of detected frameworks.
    """

    raw_content: str
    sections: dict[str, str] = field(default_factory=dict)
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)

    def extract_components(self) -> list[Component]:
        """Extract components from the architecture section.

        Returns:
            List of Component objects identified in the document.
        """
        architecture = self.sections.get("Architecture", "")
        if not architecture:
            return []

        components: list[Component] = []
        for line in architecture.split("\n"):
            # Match list items
            item_match = re.match(r"^[-*]\s+(.+)$", line.strip())
            if item_match:
                item_text = item_match.group(1).strip()
                component = self._parse_component_line(item_text)
                if component:
                    components.append(component)

        return components

    def _parse_component_line(self, line: str) -> Component | None:
        """Parse a single line to extract component information.

        Args:
            line: A line from the architecture section.

        Returns:
            Component if identified, None otherwise.
        """
        line_lower = line.lower()

        # Determine component type based on keywords
        component_type = "service"  # default
        for ctype, keywords in COMPONENT_TYPE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in line_lower:
                    component_type = ctype
                    break
            if component_type != "service":
                break

        # Extract name (first few words or up to "for"/"to")
        name_parts = []
        words = line.split()
        for word in words[:4]:  # Take first 4 words max
            if word.lower() in ("for", "to", "with"):
                break
            name_parts.append(word)

        name = " ".join(name_parts) if name_parts else line[:30]

        return Component(
            name=name,
            component_type=component_type,
            description=line,
        )

    def extract_data_flows(self) -> list[DataFlow]:
        """Extract data flows from the architecture section.

        Infers data flows between components based on their types and descriptions.

        Returns:
            List of DataFlow objects representing data movement between components.
        """
        components = self.extract_components()
        if not components:
            return []

        flows: list[DataFlow] = []

        # Keywords indicating data flow actions
        flow_keywords = ["sends", "receives", "stores", "reads", "writes", "fetches", "calls", "connects"]

        # Check each component description for flow indicators
        for component in components:
            desc_lower = component.description.lower()
            for keyword in flow_keywords:
                if keyword in desc_lower:
                    # Found a flow indicator, create a flow
                    flow = self._infer_flow_from_description(component, components)
                    if flow:
                        flows.append(flow)
                    break

        # If no explicit flows found, infer standard patterns
        if not flows:
            flows = self._infer_standard_flows(components)

        return flows

    def _infer_flow_from_description(
        self, source_component: Component, all_components: list[Component]
    ) -> DataFlow | None:
        """Infer a data flow from a component's description.

        Args:
            source_component: The component with the flow description.
            all_components: All components to find targets.

        Returns:
            DataFlow if one can be inferred, None otherwise.
        """
        desc_lower = source_component.description.lower()

        # Try to find target component mentioned in description
        for target in all_components:
            if target.name == source_component.name:
                continue
            # Check if target type keywords appear in description
            for keyword in COMPONENT_TYPE_KEYWORDS.get(target.component_type, []):
                if keyword in desc_lower:
                    return DataFlow(
                        source=source_component.name,
                        target=target.name,
                        description=source_component.description,
                    )

        # Default: create flow to generic target
        return DataFlow(
            source=source_component.name,
            target="external",
            description=source_component.description,
        )

    def _infer_standard_flows(self, components: list[Component]) -> list[DataFlow]:
        """Infer standard data flows based on component types.

        Args:
            components: List of extracted components.

        Returns:
            List of inferred DataFlow objects.
        """
        flows: list[DataFlow] = []

        # Find components by type
        apis = [c for c in components if c.component_type == "api"]
        data_stores = [c for c in components if c.component_type == "data_store"]
        auth_services = [c for c in components if c.component_type == "authentication"]

        # Standard pattern: API -> Auth
        for api in apis:
            for auth in auth_services:
                flows.append(
                    DataFlow(
                        source=api.name,
                        target=auth.name,
                        description=f"Authentication flow from {api.name} to {auth.name}",
                    )
                )

        # Standard pattern: API -> Data Store
        for api in apis:
            for ds in data_stores:
                flows.append(
                    DataFlow(
                        source=api.name,
                        target=ds.name,
                        description=f"Data persistence from {api.name} to {ds.name}",
                    )
                )

        return flows


class SecurityDocParser:
    """Parser for SECURITY.md artifacts.

    Loads and parses SECURITY.md documents from the artifact storage,
    extracting structured information about the project's security profile.

    Attributes:
        root_path: Path to the project root.
        manager: ScanStateManager for artifact access.
    """

    def __init__(self, root_path: Path) -> None:
        """Initialize the parser.

        Args:
            root_path: Path to the project root.
        """
        self.root_path = root_path
        self.manager = ScanStateManager(root_path)

    def load(self) -> str | None:
        """Load the SECURITY.md artifact content.

        Returns:
            The raw content of SECURITY.md, or None if not found.
        """
        return self.manager.read_artifact("SECURITY.md")

    def parse(self) -> ParsedSecurityDoc | None:
        """Parse the SECURITY.md artifact into structured data.

        Returns:
            ParsedSecurityDoc with extracted information, or None if artifact missing.
        """
        content = self.load()
        if content is None:
            return None

        sections = self._extract_sections(content)
        languages = self._extract_list_items(sections.get("Languages", ""))
        frameworks = self._extract_list_items(sections.get("Frameworks", ""))

        return ParsedSecurityDoc(
            raw_content=content,
            sections=sections,
            languages=languages,
            frameworks=frameworks,
        )

    def _extract_sections(self, content: str) -> dict[str, str]:
        """Extract sections from markdown content.

        Args:
            content: Raw markdown content.

        Returns:
            Dictionary mapping section headings to their content.
        """
        sections: dict[str, str] = {}
        current_section = ""
        current_content: list[str] = []

        for line in content.split("\n"):
            # Match ## headings
            heading_match = re.match(r"^##\s+(.+)$", line)
            if heading_match:
                # Save previous section
                if current_section:
                    sections[current_section] = "\n".join(current_content).strip()
                current_section = heading_match.group(1)
                current_content = []
            else:
                current_content.append(line)

        # Save last section
        if current_section:
            sections[current_section] = "\n".join(current_content).strip()

        return sections

    def _extract_list_items(self, content: str) -> list[str]:
        """Extract list items from section content.

        Args:
            content: Section content with markdown list items.

        Returns:
            List of extracted item values.
        """
        items: list[str] = []
        for line in content.split("\n"):
            # Match - item or * item patterns
            item_match = re.match(r"^[-*]\s+(.+)$", line.strip())
            if item_match:
                items.append(item_match.group(1).strip())
        return items
