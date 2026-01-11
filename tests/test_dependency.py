"""Tests for dependency validation."""

from pathlib import Path

from securevibes_mcp.storage import ScanStateManager


class TestDependencyValidator:
    """Tests for DependencyValidator class."""

    def test_validator_creation(self, tmp_path: Path):
        """Test that DependencyValidator can be created."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        assert validator is not None

    def test_assessment_has_no_dependencies(self, tmp_path: Path):
        """Test that run_assessment has no prerequisites."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        deps = validator.get_dependencies("run_assessment")
        assert deps == []

    def test_threat_modeling_requires_security_md(self, tmp_path: Path):
        """Test that run_threat_modeling requires SECURITY.md."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        deps = validator.get_dependencies("run_threat_modeling")
        assert "SECURITY.md" in deps

    def test_code_review_requires_threat_model(self, tmp_path: Path):
        """Test that run_code_review requires THREAT_MODEL.json."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        deps = validator.get_dependencies("run_code_review")
        assert "THREAT_MODEL.json" in deps

    def test_dast_requires_vulnerabilities(self, tmp_path: Path):
        """Test that run_dast requires VULNERABILITIES.json."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        deps = validator.get_dependencies("run_dast")
        assert "VULNERABILITIES.json" in deps

    def test_report_requires_all_scans(self, tmp_path: Path):
        """Test that generate_report requires all scan artifacts."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        deps = validator.get_dependencies("generate_report")
        assert "SECURITY.md" in deps

    def test_validate_passes_when_deps_exist(self, tmp_path: Path):
        """Test that validation passes when dependencies exist."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        # Create SECURITY.md artifact
        manager = ScanStateManager(tmp_path)
        manager.write_artifact("SECURITY.md", "# Security")

        validator = DependencyValidator(tmp_path)
        result = validator.validate("run_threat_modeling")
        assert result.satisfied is True
        assert result.missing == []

    def test_validate_fails_when_deps_missing(self, tmp_path: Path):
        """Test that validation fails when dependencies are missing."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        result = validator.validate("run_threat_modeling")
        assert result.satisfied is False
        assert "SECURITY.md" in result.missing

    def test_validate_assessment_always_passes(self, tmp_path: Path):
        """Test that assessment validation always passes (no deps)."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        result = validator.validate("run_assessment")
        assert result.satisfied is True
        assert result.missing == []

    def test_unknown_tool_returns_empty_deps(self, tmp_path: Path):
        """Test that unknown tools return empty dependencies."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        deps = validator.get_dependencies("unknown_tool")
        assert deps == []

    def test_validation_result_has_tool_name(self, tmp_path: Path):
        """Test that validation result includes tool name."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        result = validator.validate("run_threat_modeling")
        assert result.tool == "run_threat_modeling"

    def test_validation_result_has_required_artifacts(self, tmp_path: Path):
        """Test that validation result lists required artifacts."""
        from securevibes_mcp.agents.dependency import DependencyValidator

        validator = DependencyValidator(tmp_path)
        result = validator.validate("run_threat_modeling")
        assert result.required == ["SECURITY.md"]


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_validation_result_creation(self):
        """Test that ValidationResult can be created."""
        from securevibes_mcp.agents.dependency import ValidationResult

        result = ValidationResult(
            tool="run_assessment",
            required=[],
            missing=[],
            satisfied=True,
        )
        assert result.tool == "run_assessment"
        assert result.satisfied is True

    def test_validation_result_to_dict(self):
        """Test that ValidationResult can be converted to dict."""
        from securevibes_mcp.agents.dependency import ValidationResult

        result = ValidationResult(
            tool="run_threat_modeling",
            required=["SECURITY.md"],
            missing=["SECURITY.md"],
            satisfied=False,
        )
        d = result.to_dict()
        assert d["tool"] == "run_threat_modeling"
        assert d["satisfied"] is False
        assert "SECURITY.md" in d["missing"]
