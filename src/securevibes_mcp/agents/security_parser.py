"""Parser for SECURITY.md artifacts."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from securevibes_mcp.storage import ScanStateManager


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
