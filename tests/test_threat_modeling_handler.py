"""Tests for threat modeling tool handler."""

import json
from pathlib import Path


class TestThreatModelingHandler:
    """Tests for run_threat_modeling handler."""

    def test_handler_creation(self):
        """Test that ThreatModelingHandler can be created."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler

        handler = ThreatModelingHandler()
        assert handler is not None

    def test_run_requires_security_md(self, tmp_path: Path):
        """Test that handler requires SECURITY.md artifact."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path))

        assert result["status"] == "error"
        assert "SECURITY.md" in result["message"]

    def test_run_with_security_md_succeeds(self, tmp_path: Path):
        """Test successful threat modeling with SECURITY.md."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        # Create SECURITY.md artifact
        security_content = """# Security Assessment

## Architecture

### Languages & Frameworks
- **Languages:** Python
- **Frameworks:** FastAPI

### Components
- **User API** (api): REST API for user operations
- **PostgreSQL** (data_store): Main database

### Data Flows
- User API -> PostgreSQL: User data storage
"""
        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", security_content)

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path))

        assert result["status"] == "success"
        assert "threats_identified" in result

    def test_run_creates_threat_model_artifact(self, tmp_path: Path):
        """Test that handler creates THREAT_MODEL.json artifact."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        # Create SECURITY.md artifact
        security_content = """# Security Assessment

## Architecture

### Components
- **API** (api): REST API
"""
        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", security_content)

        handler = ThreatModelingHandler()
        handler.run(str(tmp_path))

        # Verify THREAT_MODEL.json was created
        artifact_path = tmp_path / ".securevibes" / "THREAT_MODEL.json"
        assert artifact_path.exists()

        # Verify it's valid JSON
        content = artifact_path.read_text()
        parsed = json.loads(content)
        assert parsed["version"] == "1.0"

    def test_run_returns_threat_count(self, tmp_path: Path):
        """Test that handler returns count of identified threats."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        security_content = """# Security Assessment

## Architecture

### Components
- **API** (api): REST API
- **Database** (data_store): PostgreSQL
"""
        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", security_content)

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path))

        # Should have threats for 2 components (6 each for STRIDE)
        assert result["threats_identified"] >= 12

    def test_run_with_focus_components(self, tmp_path: Path):
        """Test that handler respects focus_components parameter."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        security_content = """# Security Assessment

## Architecture
- User API endpoint for user operations
- Admin API endpoint for admin operations
- Database storage for PostgreSQL
"""
        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", security_content)

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path), focus_components=["User API endpoint"])

        # Should only have threats for User API (6 for STRIDE)
        assert result["threats_identified"] == 6
        assert result["components_analyzed"] == 1

    def test_run_returns_summary(self, tmp_path: Path):
        """Test that handler returns summary statistics."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        security_content = """# Security Assessment

## Architecture

### Components
- **API** (api): REST API
"""
        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", security_content)

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path))

        assert "summary" in result
        assert "by_severity" in result["summary"]
        assert "by_category" in result["summary"]

    def test_run_returns_artifact_path(self, tmp_path: Path):
        """Test that handler returns path to generated artifact."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        security_content = """# Security Assessment

## Architecture

### Components
- **API** (api): REST API
"""
        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", security_content)

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path))

        assert "artifact_path" in result
        assert "THREAT_MODEL.json" in result["artifact_path"]


class TestThreatModelingHandlerEdgeCases:
    """Tests for edge cases in threat modeling handler."""

    def test_run_with_empty_security_md(self, tmp_path: Path):
        """Test handling of empty SECURITY.md."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", "# Empty Document")

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path))

        # Should succeed but with 0 threats
        assert result["status"] == "success"
        assert result["threats_identified"] == 0

    def test_run_with_no_components(self, tmp_path: Path):
        """Test handling when no components are found."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        security_content = """# Security Assessment

## Overview
This is a security document with no components.
"""
        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", security_content)

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path))

        assert result["status"] == "success"
        assert result["threats_identified"] == 0
        assert result["components_analyzed"] == 0

    def test_run_with_invalid_focus_components(self, tmp_path: Path):
        """Test handling of non-existent focus components."""
        from securevibes_mcp.agents.threat_modeling_handler import ThreatModelingHandler
        from securevibes_mcp.storage import ScanStateManager

        security_content = """# Security Assessment

## Architecture

### Components
- **API** (api): REST API
"""
        storage = ScanStateManager(tmp_path)
        storage.write_artifact("SECURITY.md", security_content)

        handler = ThreatModelingHandler()
        result = handler.run(str(tmp_path), focus_components=["NonExistent"])

        # Should warn about invalid components but still succeed
        assert result["status"] == "success"
        assert result["threats_identified"] == 0
        assert "invalid_components" in result
