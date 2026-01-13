"""Tests for code review handler."""

import json
from pathlib import Path

import pytest


class TestCodeReviewHandler:
    """Tests for CodeReviewHandler class."""

    def test_handler_creation(self):
        """Test that CodeReviewHandler can be created."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        handler = CodeReviewHandler()
        assert handler is not None

    def test_handler_requires_threat_model(self, tmp_path: Path):
        """Test that handler fails without THREAT_MODEL.json."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        handler = CodeReviewHandler()
        result = handler.run(project_path=str(tmp_path))

        assert result["status"] == "error"
        assert "THREAT_MODEL.json" in result["message"]

    def test_handler_runs_with_threat_model(self, tmp_path: Path):
        """Test that handler runs with valid threat model."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        # Create .securevibes directory and threat model
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0.0",
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "Spoofing",
                    "component": "AuthService",
                    "severity": "high",
                    "description": "Test threat",
                    "attack_vector": "Test attack",
                    "impact": "Test impact",
                }
            ],
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        # Create a source file with a vulnerability
        (tmp_path / "auth.py").write_text("password = 'secret123'")

        handler = CodeReviewHandler()
        result = handler.run(project_path=str(tmp_path))

        assert result["status"] == "success"
        assert "vulnerabilities_found" in result
        assert "artifact_path" in result

    def test_handler_creates_vulnerabilities_artifact(self, tmp_path: Path):
        """Test that handler creates VULNERABILITIES.json artifact."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        # Create .securevibes directory and threat model
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0.0",
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "InfoDisclosure",
                    "component": "Config",
                    "severity": "high",
                    "description": "Test threat",
                    "attack_vector": "Test attack",
                    "impact": "Test impact",
                }
            ],
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        # Create a source file with a vulnerability
        (tmp_path / "config.py").write_text("DEBUG = True")

        handler = CodeReviewHandler()
        result = handler.run(project_path=str(tmp_path))

        assert result["status"] == "success"

        # Check artifact was created
        artifact_path = securevibes_dir / "VULNERABILITIES.json"
        assert artifact_path.exists()

        # Check artifact content
        content = json.loads(artifact_path.read_text())
        assert "vulnerabilities" in content
        assert "summary" in content

    def test_handler_maps_matches_to_threats(self, tmp_path: Path):
        """Test that handler maps vulnerability matches to threat IDs."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        # Create .securevibes directory and threat model
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0.0",
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "Spoofing",
                    "component": "Auth",
                    "severity": "critical",
                    "description": "Auth threat",
                    "attack_vector": "Token theft",
                    "impact": "Unauthorized access",
                }
            ],
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        # Create file with Spoofing vulnerability (hardcoded password)
        (tmp_path / "auth.py").write_text("password = 'hardcoded123'")

        handler = CodeReviewHandler()
        result = handler.run(project_path=str(tmp_path))

        assert result["status"] == "success"

        # Check that vulnerability was mapped to threat
        artifact_path = securevibes_dir / "VULNERABILITIES.json"
        content = json.loads(artifact_path.read_text())

        confirmed = [v for v in content["vulnerabilities"] if v["status"] == "confirmed"]
        assert len(confirmed) > 0
        assert confirmed[0]["threat_id"] == "THREAT-001"

    def test_handler_includes_not_confirmed_threats(self, tmp_path: Path):
        """Test that handler includes not_confirmed for unmatched threats."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        # Create .securevibes directory and threat model
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0.0",
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "DoS",
                    "component": "API",
                    "severity": "medium",
                    "description": "DoS threat",
                    "attack_vector": "Resource exhaustion",
                    "impact": "Service unavailable",
                }
            ],
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        # Create clean file with no vulnerabilities
        (tmp_path / "clean.py").write_text("def add(a, b): return a + b")

        handler = CodeReviewHandler()
        result = handler.run(project_path=str(tmp_path))

        assert result["status"] == "success"
        assert result["not_confirmed"] == 1

        # Check artifact
        artifact_path = securevibes_dir / "VULNERABILITIES.json"
        content = json.loads(artifact_path.read_text())

        not_confirmed = [v for v in content["vulnerabilities"] if v["status"] == "not_confirmed"]
        assert len(not_confirmed) == 1
        assert not_confirmed[0]["threat_id"] == "THREAT-001"

    def test_handler_respects_focus_components(self, tmp_path: Path):
        """Test that handler respects focus_components filter."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        # Create .securevibes directory and threat model
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0.0",
            "threats": [
                {
                    "id": "THREAT-001",
                    "category": "Spoofing",
                    "component": "Auth",
                    "severity": "high",
                    "description": "Test threat",
                    "attack_vector": "Test attack",
                    "impact": "Test impact",
                }
            ],
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        # Create files in different directories
        auth_dir = tmp_path / "auth"
        auth_dir.mkdir()
        (auth_dir / "login.py").write_text("password = 'secret'")

        other_dir = tmp_path / "other"
        other_dir.mkdir()
        (other_dir / "utils.py").write_text("password = 'other_secret'")

        handler = CodeReviewHandler()
        result = handler.run(
            project_path=str(tmp_path),
            focus_components=["auth"],
        )

        assert result["status"] == "success"
        assert result["focus_components"] == ["auth"]

        # Check that only auth vulnerabilities were found
        artifact_path = securevibes_dir / "VULNERABILITIES.json"
        content = json.loads(artifact_path.read_text())

        confirmed = [v for v in content["vulnerabilities"] if v["status"] == "confirmed"]
        for vuln in confirmed:
            assert "auth" in vuln["file_path"]


class TestHandlerValidation:
    """Tests for handler input validation."""

    def test_handler_handles_empty_threats(self, tmp_path: Path):
        """Test that handler handles threat model with no threats."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        # Create .securevibes directory and empty threat model
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0.0",
            "threats": [],
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        handler = CodeReviewHandler()
        result = handler.run(project_path=str(tmp_path))

        assert result["status"] == "error"
        assert "No threats found" in result["message"]

    def test_handler_handles_invalid_threat_entries(self, tmp_path: Path):
        """Test that handler handles invalid threat entries."""
        from securevibes_mcp.agents.code_review_handler import CodeReviewHandler

        # Create .securevibes directory and threat model with invalid entry
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()

        threat_model = {
            "version": "1.0.0",
            "threats": [
                {
                    # Missing required fields: id, category, component, severity
                    "description": "Incomplete threat",
                }
            ],
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(json.dumps(threat_model))

        handler = CodeReviewHandler()
        result = handler.run(project_path=str(tmp_path))

        assert result["status"] == "error"
        assert "Invalid threat entries" in result["message"]
