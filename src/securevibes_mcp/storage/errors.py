"""Storage error definitions."""

from typing import Any


class StorageError(Exception):
    """Error raised by storage operations.

    Attributes:
        message: Human-readable error message.
        code: Error code for programmatic handling.
        path: Optional path related to the error.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str,
        path: str | None = None,
    ) -> None:
        """Initialize storage error.

        Args:
            message: Human-readable error message.
            code: Error code for programmatic handling.
            path: Optional path related to the error.
        """
        self.message = message
        self.code = code
        self.path = path
        super().__init__(f"[{code}] {message}")

    def to_dict(self) -> dict[str, Any]:
        """Convert error to dictionary format.

        Returns:
            Dictionary with error details.
        """
        result: dict[str, Any] = {
            "error": True,
            "code": self.code,
            "message": self.message,
        }
        if self.path is not None:
            result["path"] = self.path
        return result
