"""Threat templates for STRIDE analysis."""

from dataclasses import dataclass

# STRIDE categories
STRIDE_CATEGORIES: list[str] = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "InfoDisclosure",
    "DoS",
    "EoP",
]


@dataclass
class ThreatTemplate:
    """Template for a security threat.

    Attributes:
        category: STRIDE category (Spoofing, Tampering, etc.).
        component_type: Type of component this applies to.
        description: Description of the threat.
        attack_vector: How the threat could be exploited.
        impact: Potential business/security impact.
        severity: Default severity (critical, high, medium, low).
    """

    category: str
    component_type: str
    description: str
    attack_vector: str
    impact: str
    severity: str


# Predefined threat templates for API components
API_TEMPLATES: list[ThreatTemplate] = [
    ThreatTemplate(
        category="Spoofing",
        component_type="api",
        description="Identity spoofing via forged or stolen authentication tokens",
        attack_vector="Token theft, session hijacking, or credential stuffing",
        impact="Unauthorized access to protected resources",
        severity="high",
    ),
    ThreatTemplate(
        category="Tampering",
        component_type="api",
        description="Request tampering through parameter manipulation",
        attack_vector="Modifying request parameters, headers, or body content",
        impact="Data corruption, unauthorized actions, or privilege escalation",
        severity="high",
    ),
    ThreatTemplate(
        category="Repudiation",
        component_type="api",
        description="Actions performed without adequate audit logging",
        attack_vector="Exploiting gaps in logging to deny performed actions",
        impact="Inability to trace malicious activity or prove compliance",
        severity="medium",
    ),
    ThreatTemplate(
        category="InfoDisclosure",
        component_type="api",
        description="Sensitive data exposure through API responses",
        attack_vector="Verbose error messages, improper filtering, or response data leakage",
        impact="Exposure of PII, credentials, or internal system details",
        severity="high",
    ),
    ThreatTemplate(
        category="DoS",
        component_type="api",
        description="API denial of service through resource exhaustion",
        attack_vector="Flooding endpoints, slow requests, or resource-intensive queries",
        impact="Service unavailability affecting legitimate users",
        severity="medium",
    ),
    ThreatTemplate(
        category="EoP",
        component_type="api",
        description="Privilege escalation through broken access controls",
        attack_vector="IDOR, missing function-level access control, or role manipulation",
        impact="Unauthorized access to admin functions or other users' data",
        severity="critical",
    ),
]

# Predefined threat templates for data store components
DATA_STORE_TEMPLATES: list[ThreatTemplate] = [
    ThreatTemplate(
        category="Spoofing",
        component_type="data_store",
        description="Database connection spoofing or credential theft",
        attack_vector="Man-in-the-middle attacks or stolen connection strings",
        impact="Unauthorized database access",
        severity="critical",
    ),
    ThreatTemplate(
        category="Tampering",
        component_type="data_store",
        description="Data tampering through injection attacks",
        attack_vector="SQL injection, NoSQL injection, or ORM manipulation",
        impact="Data corruption, unauthorized modifications, or data loss",
        severity="critical",
    ),
    ThreatTemplate(
        category="Repudiation",
        component_type="data_store",
        description="Database changes without audit trail",
        attack_vector="Direct database modifications bypassing application logging",
        impact="Inability to track data changes or identify responsible parties",
        severity="medium",
    ),
    ThreatTemplate(
        category="InfoDisclosure",
        component_type="data_store",
        description="Sensitive data exposure through database access",
        attack_vector="Unauthorized queries, backup exposure, or insufficient encryption",
        impact="Mass data breach affecting all stored records",
        severity="critical",
    ),
    ThreatTemplate(
        category="DoS",
        component_type="data_store",
        description="Database denial of service",
        attack_vector="Resource-intensive queries, connection pool exhaustion, or disk filling",
        impact="Application unavailability due to database failure",
        severity="high",
    ),
    ThreatTemplate(
        category="EoP",
        component_type="data_store",
        description="Database privilege escalation",
        attack_vector="Exploiting stored procedures or database user permissions",
        impact="Full database control or server compromise",
        severity="critical",
    ),
]

# Predefined threat templates for authentication components
AUTH_TEMPLATES: list[ThreatTemplate] = [
    ThreatTemplate(
        category="Spoofing",
        component_type="authentication",
        description="Authentication bypass or credential compromise",
        attack_vector="Brute force, credential stuffing, or authentication logic flaws",
        impact="Complete identity takeover",
        severity="critical",
    ),
    ThreatTemplate(
        category="Tampering",
        component_type="authentication",
        description="Token or session tampering",
        attack_vector="JWT manipulation, session fixation, or cookie tampering",
        impact="Unauthorized session access or privilege elevation",
        severity="critical",
    ),
    ThreatTemplate(
        category="Repudiation",
        component_type="authentication",
        description="Authentication events not properly logged",
        attack_vector="Failed login attempts or session changes not recorded",
        impact="Unable to detect or investigate account compromises",
        severity="medium",
    ),
    ThreatTemplate(
        category="InfoDisclosure",
        component_type="authentication",
        description="Credential or token leakage",
        attack_vector="Tokens in URLs, logging credentials, or insecure storage",
        impact="Credential exposure enabling account takeover",
        severity="critical",
    ),
    ThreatTemplate(
        category="DoS",
        component_type="authentication",
        description="Authentication service denial of service",
        attack_vector="Account lockout abuse or authentication endpoint flooding",
        impact="Users unable to authenticate, service disruption",
        severity="high",
    ),
    ThreatTemplate(
        category="EoP",
        component_type="authentication",
        description="Authentication bypass leading to elevated privileges",
        attack_vector="Role claim manipulation, admin bypass, or multi-factor bypass",
        impact="Unauthorized admin or privileged access",
        severity="critical",
    ),
]

# Predefined threat templates for external integration components
EXTERNAL_TEMPLATES: list[ThreatTemplate] = [
    ThreatTemplate(
        category="Spoofing",
        component_type="external_integration",
        description="Third-party service impersonation",
        attack_vector="Spoofed webhooks, DNS hijacking, or certificate issues",
        impact="Accepting malicious data as legitimate",
        severity="high",
    ),
    ThreatTemplate(
        category="Tampering",
        component_type="external_integration",
        description="Data tampering in transit to external services",
        attack_vector="Man-in-the-middle attacks or API response manipulation",
        impact="Corrupted data exchange with partners",
        severity="high",
    ),
    ThreatTemplate(
        category="Repudiation",
        component_type="external_integration",
        description="External API calls not logged or verified",
        attack_vector="Untracked third-party interactions",
        impact="Unable to reconcile external service usage or disputes",
        severity="low",
    ),
    ThreatTemplate(
        category="InfoDisclosure",
        component_type="external_integration",
        description="Sensitive data exposure to third parties",
        attack_vector="Over-sharing data with external services or insecure transmission",
        impact="PII or business data leaked to external parties",
        severity="high",
    ),
    ThreatTemplate(
        category="DoS",
        component_type="external_integration",
        description="External service dependency failure",
        attack_vector="Third-party service outage or rate limiting",
        impact="Application features unavailable due to external dependency",
        severity="medium",
    ),
    ThreatTemplate(
        category="EoP",
        component_type="external_integration",
        description="Exploiting external service trust relationships",
        attack_vector="Compromised third-party credentials or excessive permissions",
        impact="Unauthorized actions through trusted external services",
        severity="high",
    ),
]


class ThreatTemplateRegistry:
    """Registry of threat templates organized by component type.

    Provides access to predefined threat templates for STRIDE analysis.
    """

    def __init__(self) -> None:
        """Initialize the registry with predefined templates."""
        self._templates: dict[str, list[ThreatTemplate]] = {
            "api": API_TEMPLATES,
            "data_store": DATA_STORE_TEMPLATES,
            "authentication": AUTH_TEMPLATES,
            "external_integration": EXTERNAL_TEMPLATES,
        }

    def get_templates_for_type(self, component_type: str) -> list[ThreatTemplate]:
        """Get threat templates for a specific component type.

        Args:
            component_type: The type of component.

        Returns:
            List of ThreatTemplate objects for that component type.
        """
        return self._templates.get(component_type, [])

    def get_all_templates(self) -> list[ThreatTemplate]:
        """Get all threat templates from the registry.

        Returns:
            List of all ThreatTemplate objects.
        """
        all_templates: list[ThreatTemplate] = []
        for templates in self._templates.values():
            all_templates.extend(templates)
        return all_templates
