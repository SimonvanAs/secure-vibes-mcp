"""Severity classification for STRIDE threats."""

from dataclasses import replace

from securevibes_mcp.agents.stride_analyzer import ThreatFinding

# CVSS-aligned severity levels (lowercase)
SEVERITY_LEVELS: list[str] = ["critical", "high", "medium", "low"]

# CVSS score ranges for each severity level
CVSS_RANGES: dict[str, tuple[float, float]] = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
}

# Severity order (higher = more severe)
SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class SeverityClassifier:
    """Classifier for CVSS-aligned severity levels.

    Provides validation, normalization, and comparison of severity levels.
    """

    def validate(self, severity: str) -> bool:
        """Check if a severity level is valid.

        Args:
            severity: The severity level to validate.

        Returns:
            True if valid, False otherwise.
        """
        return severity.lower() in SEVERITY_LEVELS

    def normalize(self, severity: str) -> str:
        """Normalize a severity level to lowercase.

        Args:
            severity: The severity level to normalize.

        Returns:
            Normalized lowercase severity, or 'medium' if invalid.
        """
        normalized = severity.lower()
        if normalized in SEVERITY_LEVELS:
            return normalized
        return "medium"

    def get_cvss_range(self, severity: str) -> tuple[float, float]:
        """Get the CVSS score range for a severity level.

        Args:
            severity: The severity level.

        Returns:
            Tuple of (min_score, max_score) for the severity level.
        """
        normalized = self.normalize(severity)
        return CVSS_RANGES.get(normalized, CVSS_RANGES["medium"])

    def get_order(self, severity: str) -> int:
        """Get the numeric order for a severity level.

        Args:
            severity: The severity level.

        Returns:
            Numeric order (4=critical, 3=high, 2=medium, 1=low, 0=unknown).
        """
        normalized = severity.lower()
        return SEVERITY_ORDER.get(normalized, 0)

    def compare(self, severity1: str, severity2: str) -> int:
        """Compare two severity levels.

        Args:
            severity1: First severity level.
            severity2: Second severity level.

        Returns:
            Positive if severity1 > severity2, negative if less, 0 if equal.
        """
        return self.get_order(severity1) - self.get_order(severity2)

    def classify_threat(self, threat: ThreatFinding) -> ThreatFinding:
        """Classify and normalize severity for a threat.

        Args:
            threat: The threat finding to classify.

        Returns:
            ThreatFinding with normalized severity.
        """
        normalized_severity = self.normalize(threat.severity)
        return replace(threat, severity=normalized_severity)

    def classify_threats(self, threats: list[ThreatFinding]) -> list[ThreatFinding]:
        """Classify and normalize severity for multiple threats.

        Args:
            threats: List of threat findings to classify.

        Returns:
            List of ThreatFindings with normalized severities.
        """
        return [self.classify_threat(threat) for threat in threats]
