"""Component filtering for targeted threat analysis."""

from securevibes_mcp.agents.security_parser import Component


class ComponentFilter:
    """Filter for selecting specific components for threat analysis.

    Allows users to focus threat analysis on a subset of components
    rather than analyzing all discovered components.
    """

    def __init__(
        self,
        focus_components: list[str] | None = None,
        case_insensitive: bool = False,
    ) -> None:
        """Initialize the filter.

        Args:
            focus_components: List of component names to focus on.
                If empty or None, all components will be included.
            case_insensitive: Whether to match names case-insensitively.
        """
        self.focus_components = focus_components or []
        self.case_insensitive = case_insensitive

    def filter(self, components: list[Component]) -> list[Component]:
        """Filter components to only those in the focus list.

        Args:
            components: List of components to filter.

        Returns:
            Filtered list containing only focused components.
            Returns all components if focus_components is empty.
        """
        if not self.focus_components:
            return components

        if self.case_insensitive:
            focus_lower = {name.lower() for name in self.focus_components}
            return [c for c in components if c.name.lower() in focus_lower]
        else:
            focus_set = set(self.focus_components)
            return [c for c in components if c.name in focus_set]

    def validate(
        self, components: list[Component]
    ) -> tuple[list[str], list[str]]:
        """Validate focus_components against available components.

        Args:
            components: List of available components.

        Returns:
            Tuple of (valid_names, invalid_names).
        """
        if not self.focus_components:
            return [], []

        available_names = {c.name for c in components}
        if self.case_insensitive:
            available_lower = {name.lower() for name in available_names}
            valid = [
                name for name in self.focus_components
                if name.lower() in available_lower
            ]
            invalid = [
                name for name in self.focus_components
                if name.lower() not in available_lower
            ]
        else:
            valid = [
                name for name in self.focus_components
                if name in available_names
            ]
            invalid = [
                name for name in self.focus_components
                if name not in available_names
            ]

        return valid, invalid
