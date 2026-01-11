"""SECURITY.md document generation."""

from securevibes_mcp.agents.scanner import ScanResult

# Security considerations for different frameworks
FRAMEWORK_SECURITY_NOTES: dict[str, list[str]] = {
    "Flask": [
        "Ensure Flask sessions use secure cookies with `SESSION_COOKIE_SECURE=True`",
        "Implement CSRF protection using Flask-WTF or similar",
        "Use Flask-Talisman for security headers",
        "Validate and sanitize all user inputs",
    ],
    "Django": [
        "Django's built-in CSRF protection is enabled by default",
        "Use Django's ORM to prevent SQL injection",
        "Enable SECURE_SSL_REDIRECT in production",
        "Review ALLOWED_HOSTS configuration",
        "Consider using django-csp for Content Security Policy",
    ],
    "FastAPI": [
        "Implement proper authentication with OAuth2 or JWT",
        "Use Pydantic models for input validation",
        "Enable CORS only for trusted origins",
        "Implement rate limiting for API endpoints",
    ],
    "Express": [
        "Use helmet.js for security headers",
        "Implement rate limiting with express-rate-limit",
        "Sanitize user inputs to prevent XSS and injection attacks",
        "Use HTTPS in production with proper TLS configuration",
        "Implement CSRF protection for stateful sessions",
    ],
    "React": [
        "Avoid dangerouslySetInnerHTML unless absolutely necessary",
        "Sanitize any HTML content from user input or APIs",
        "Store sensitive data securely, not in localStorage",
        "Implement proper authentication token handling",
    ],
    "Next.js": [
        "Review API routes for proper authentication",
        "Use Next.js built-in security headers",
        "Implement proper CSRF protection for mutations",
        "Be cautious with server-side data exposure to client",
    ],
}

# General security notes by language
LANGUAGE_SECURITY_NOTES: dict[str, list[str]] = {
    "Python": [
        "Use parameterized queries to prevent SQL injection",
        "Avoid using eval() or exec() with user input",
        "Keep dependencies updated and audit with pip-audit",
    ],
    "JavaScript": [
        "Validate and sanitize all user inputs",
        "Use Content Security Policy headers",
        "Audit dependencies with npm audit regularly",
    ],
    "TypeScript": [
        "Leverage TypeScript's type system for safer code",
        "Validate runtime data even with type definitions",
        "Audit dependencies with npm audit regularly",
    ],
    "Go": [
        "Use the html/template package to prevent XSS",
        "Avoid using unsafe package unless necessary",
        "Use crypto/rand for secure random number generation",
    ],
}


class SecurityDocGenerator:
    """Generates SECURITY.md documentation from scan results.

    Attributes:
        scan_result: The codebase scan result to generate documentation for.
    """

    def __init__(self, scan_result: ScanResult) -> None:
        """Initialize the generator.

        Args:
            scan_result: The scan result to generate documentation from.
        """
        self.scan_result = scan_result

    def generate(self) -> str:
        """Generate the SECURITY.md document.

        Returns:
            The generated markdown document as a string.
        """
        sections = [
            self._generate_header(),
            self._generate_overview(),
            self._generate_architecture(),
            self._generate_security_considerations(),
            self._generate_footer(),
        ]

        return "\n\n".join(sections)

    def _generate_header(self) -> str:
        """Generate the document header."""
        return "# Security Assessment\n\nThis document provides a security baseline for the codebase."

    def _generate_overview(self) -> str:
        """Generate the project overview section."""
        lines = ["## Project Overview"]

        lines.append(f"\n**Files Analyzed:** {self.scan_result.file_count}")
        lines.append(f"**Root Path:** `{self.scan_result.root_path}`")

        return "\n".join(lines)

    def _generate_architecture(self) -> str:
        """Generate the architecture/technology stack section."""
        lines = ["## Technology Stack"]

        # Languages
        if self.scan_result.languages:
            lines.append("\n### Languages")
            for lang in self.scan_result.languages:
                count = self.scan_result.language_stats.get(lang, 0)
                lines.append(f"- **{lang}**: {count} files")
        else:
            lines.append("\n*No programming languages detected.*")

        # Frameworks
        if self.scan_result.frameworks:
            lines.append("\n### Frameworks & Libraries")
            for framework in self.scan_result.frameworks:
                lines.append(f"- {framework}")

        return "\n".join(lines)

    def _generate_security_considerations(self) -> str:
        """Generate the security considerations section."""
        lines = ["## Security Considerations"]

        # Framework-specific notes
        framework_notes_added = False
        for framework in self.scan_result.frameworks:
            if framework in FRAMEWORK_SECURITY_NOTES:
                lines.append(f"\n### {framework} Security")
                for note in FRAMEWORK_SECURITY_NOTES[framework]:
                    lines.append(f"- {note}")
                framework_notes_added = True

        # Language-specific notes (if no framework notes)
        if not framework_notes_added:
            for lang in self.scan_result.languages[:2]:  # Top 2 languages
                if lang in LANGUAGE_SECURITY_NOTES:
                    lines.append(f"\n### {lang} Security Best Practices")
                    for note in LANGUAGE_SECURITY_NOTES[lang]:
                        lines.append(f"- {note}")

        # General security notes
        lines.append("\n### General Security Recommendations")
        lines.append("- Keep all dependencies up to date")
        lines.append("- Implement proper authentication and authorization")
        lines.append("- Use HTTPS for all communications")
        lines.append("- Follow the principle of least privilege")
        lines.append("- Implement proper logging and monitoring")

        return "\n".join(lines)

    def _generate_footer(self) -> str:
        """Generate the document footer."""
        return (
            "---\n\n"
            "*This security assessment was generated automatically by SecureVibes MCP. "
            "It provides a baseline and should be supplemented with thorough security review.*"
        )
