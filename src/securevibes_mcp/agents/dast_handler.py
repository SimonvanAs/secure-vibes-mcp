"""DAST handler for orchestrating vulnerability testing."""

from pathlib import Path
from typing import Any

import httpx

from securevibes_mcp.agents.dast_output import (
    DASTValidation,
    DASTValidationOutput,
    DASTValidationWriter,
)
from securevibes_mcp.agents.dast_tester import DASTTester
from securevibes_mcp.agents.vulnerability_reader import VulnerabilityReader


class DASTHandler:
    """Handler for DAST testing operations.

    Orchestrates the DAST testing workflow:
    1. Reads confirmed vulnerabilities from VULNERABILITIES.json
    2. Tests each vulnerability against the target URL
    3. Writes results to DAST_VALIDATION.json
    """

    def __init__(self) -> None:
        """Initialize the handler."""
        pass

    async def run(
        self,
        project_path: Path,
        target_url: str,
        vulnerability_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run DAST testing on confirmed vulnerabilities.

        Args:
            project_path: Path to the project root.
            target_url: Base URL of the target application.
            vulnerability_ids: Optional list of specific vulnerability IDs to test.
                If None, tests all confirmed vulnerabilities.

        Returns:
            Dictionary with status and summary information.
        """
        # Read vulnerabilities
        reader = VulnerabilityReader(root_path=project_path)
        vuln_data = reader.read()

        if vuln_data is None:
            return {
                "status": "error",
                "message": "VULNERABILITIES.json not found. Run code review first.",
            }

        # Get vulnerabilities to test
        if vulnerability_ids:
            vulnerabilities = reader.filter_by_ids(vulnerability_ids)
            # Filter to only confirmed ones
            vulnerabilities = [
                v for v in vulnerabilities if v.get("status") == "confirmed"
            ]
        else:
            vulnerabilities = reader.get_confirmed()

        # Check if we have anything to test
        if not vulnerabilities:
            # Still write an output artifact
            output = DASTValidationOutput(target_url=target_url)
            writer = DASTValidationWriter(root_path=project_path)
            writer.write(output)

            return {
                "status": "success",
                "message": "No confirmed vulnerabilities to test.",
                "tested": 0,
                "exploitable": 0,
                "not_exploitable": 0,
            }

        # Create tester
        tester = DASTTester(target_url=target_url)

        # Create output container
        output = DASTValidationOutput(target_url=target_url)

        # Test each vulnerability
        try:
            for vuln in vulnerabilities:
                result = await tester.test_vulnerability(vuln)

                # Convert TestResult to DASTValidation
                validation = DASTValidation(
                    vulnerability_id=result.vulnerability_id,
                    exploitable=result.exploitable,
                    evidence=result.evidence,
                    http_status=result.http_status,
                    response_time_ms=result.response_time_ms,
                    test_payload=result.test_payload,
                    notes=result.notes,
                    severity=vuln.get("severity"),
                )
                output.add_validation(validation)

        except httpx.ConnectError as e:
            return {
                "status": "error",
                "message": f"Connection error: Could not connect to {target_url}. {e}",
            }
        except httpx.HTTPError as e:
            return {
                "status": "error",
                "message": f"HTTP error during testing: {e}",
            }

        # Write output artifact
        writer = DASTValidationWriter(root_path=project_path)
        writer.write(output)

        # Build summary
        summary = output.get_summary()

        return {
            "status": "success",
            "message": f"Tested {summary['total_tested']} vulnerabilities against {target_url}",
            "tested": summary["total_tested"],
            "exploitable": summary["exploitable"],
            "not_exploitable": summary["not_exploitable"],
            "by_severity": summary["by_severity"],
            "artifact": "DAST_VALIDATION.json",
        }
