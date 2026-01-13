"""Tests for DAST output structures."""

import json
from pathlib import Path

import pytest


class TestDASTValidation:
    """Tests for DASTValidation dataclass."""

    def test_validation_creation(self):
        """Test that DASTValidation can be created."""
        from securevibes_mcp.agents.dast_output import DASTValidation

        validation = DASTValidation(
            vulnerability_id="VULN-001",
            exploitable=True,
            evidence="SQL error detected",
            http_status=500,
            response_time_ms=150.5,
            test_payload="' OR '1'='1",
            notes="Confirmed via error-based detection",
        )

        assert validation.vulnerability_id == "VULN-001"
        assert validation.exploitable is True
        assert validation.evidence == "SQL error detected"
        assert validation.http_status == 500
        assert validation.response_time_ms == 150.5
        assert validation.test_payload == "' OR '1'='1"

    def test_validation_to_dict(self):
        """Test that DASTValidation can be converted to dict."""
        from securevibes_mcp.agents.dast_output import DASTValidation

        validation = DASTValidation(
            vulnerability_id="VULN-001",
            exploitable=True,
            evidence="SQL error detected",
            http_status=500,
            response_time_ms=150.5,
            test_payload="' OR '1'='1",
            notes="Confirmed",
        )

        data = validation.to_dict()

        assert data["vulnerability_id"] == "VULN-001"
        assert data["exploitable"] is True
        assert data["http_status"] == 500


class TestDASTValidationOutput:
    """Tests for DASTValidationOutput class."""

    def test_output_creation(self):
        """Test that DASTValidationOutput can be created."""
        from securevibes_mcp.agents.dast_output import DASTValidationOutput

        output = DASTValidationOutput(target_url="http://localhost:8080")

        assert output is not None
        assert output.target_url == "http://localhost:8080"
        assert output.validations == []

    def test_add_validation(self):
        """Test adding validations to output."""
        from securevibes_mcp.agents.dast_output import (
            DASTValidation,
            DASTValidationOutput,
        )

        output = DASTValidationOutput(target_url="http://localhost:8080")

        validation = DASTValidation(
            vulnerability_id="VULN-001",
            exploitable=True,
            evidence="SQL error",
            http_status=500,
            response_time_ms=150.0,
            test_payload="' OR '1'='1",
            notes="",
        )

        output.add_validation(validation)

        assert len(output.validations) == 1
        assert output.validations[0].vulnerability_id == "VULN-001"

    def test_get_summary(self):
        """Test getting summary statistics."""
        from securevibes_mcp.agents.dast_output import (
            DASTValidation,
            DASTValidationOutput,
        )

        output = DASTValidationOutput(target_url="http://localhost:8080")

        # Add some validations
        output.add_validation(
            DASTValidation(
                vulnerability_id="VULN-001",
                exploitable=True,
                evidence="SQL error",
                severity="critical",
            )
        )
        output.add_validation(
            DASTValidation(
                vulnerability_id="VULN-002",
                exploitable=False,
                evidence="Not exploitable",
                severity="high",
            )
        )
        output.add_validation(
            DASTValidation(
                vulnerability_id="VULN-003",
                exploitable=True,
                evidence="XSS reflected",
                severity="critical",
            )
        )

        summary = output.get_summary()

        assert summary["total_tested"] == 3
        assert summary["exploitable"] == 2
        assert summary["not_exploitable"] == 1
        assert summary["by_severity"]["critical"] == 2
        assert summary["by_severity"]["high"] == 1

    def test_to_dict(self):
        """Test converting output to dictionary."""
        from securevibes_mcp.agents.dast_output import (
            DASTValidation,
            DASTValidationOutput,
        )

        output = DASTValidationOutput(target_url="http://localhost:8080")
        output.add_validation(
            DASTValidation(
                vulnerability_id="VULN-001",
                exploitable=True,
                evidence="SQL error",
            )
        )

        data = output.to_dict()

        assert data["version"] == "1.0.0"
        assert "generated_at" in data
        assert data["target_url"] == "http://localhost:8080"
        assert len(data["validations"]) == 1
        assert "summary" in data

    def test_to_json(self):
        """Test converting output to JSON string."""
        from securevibes_mcp.agents.dast_output import DASTValidationOutput

        output = DASTValidationOutput(target_url="http://localhost:8080")

        json_str = output.to_json()

        # Should be valid JSON
        data = json.loads(json_str)
        assert data["target_url"] == "http://localhost:8080"


class TestDASTValidationWriter:
    """Tests for DASTValidationWriter class."""

    def test_writer_creation(self, tmp_path: Path):
        """Test that DASTValidationWriter can be created."""
        from securevibes_mcp.agents.dast_output import DASTValidationWriter

        writer = DASTValidationWriter(root_path=tmp_path)

        assert writer is not None

    def test_writer_writes_artifact(self, tmp_path: Path):
        """Test that writer writes DAST_VALIDATION.json artifact."""
        from securevibes_mcp.agents.dast_output import (
            DASTValidation,
            DASTValidationOutput,
            DASTValidationWriter,
        )

        # Create output with validation
        output = DASTValidationOutput(target_url="http://localhost:8080")
        output.add_validation(
            DASTValidation(
                vulnerability_id="VULN-001",
                exploitable=True,
                evidence="SQL error detected",
            )
        )

        # Write artifact
        writer = DASTValidationWriter(root_path=tmp_path)
        writer.write(output)

        # Verify file exists
        artifact_path = tmp_path / ".securevibes" / "DAST_VALIDATION.json"
        assert artifact_path.exists()

        # Verify content
        data = json.loads(artifact_path.read_text())
        assert data["target_url"] == "http://localhost:8080"
        assert len(data["validations"]) == 1
        assert data["validations"][0]["exploitable"] is True
