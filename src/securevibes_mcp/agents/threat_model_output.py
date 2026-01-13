"""THREAT_MODEL.json output serialization and storage."""

import json
from pathlib import Path

from securevibes_mcp.agents.threat_model_builder import ThreatModel
from securevibes_mcp.storage import ScanStateManager


class ThreatModelSerializer:
    """Serializer for converting ThreatModel to JSON format.

    Produces properly formatted JSON suitable for storage and retrieval.
    """

    def serialize(self, model: ThreatModel) -> str:
        """Serialize a ThreatModel to JSON string.

        Args:
            model: The ThreatModel to serialize.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(model.to_dict(), indent=2)


class ThreatModelWriter:
    """Writer for storing THREAT_MODEL.json artifacts.

    Uses ScanStateManager to persist threat model to the project's
    .securevibes directory.
    """

    ARTIFACT_NAME = "THREAT_MODEL.json"

    def __init__(self, root_path: Path) -> None:
        """Initialize the writer.

        Args:
            root_path: Root path of the project.
        """
        self.root_path = root_path
        self.storage = ScanStateManager(root_path)
        self.serializer = ThreatModelSerializer()

    def get_artifact_path(self) -> Path:
        """Get the path where the artifact will be stored.

        Returns:
            Path to the THREAT_MODEL.json artifact.
        """
        return self.root_path / ".securevibes" / self.ARTIFACT_NAME

    def write(self, model: ThreatModel) -> bool:
        """Write a ThreatModel to storage.

        Args:
            model: The ThreatModel to write.

        Returns:
            True if successful.
        """
        content = self.serializer.serialize(model)
        self.storage.write_artifact(self.ARTIFACT_NAME, content)
        return True
