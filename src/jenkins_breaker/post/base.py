"""
Base classes for post-exploitation modules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class PostResult:
    """Result of post-exploitation module execution."""

    module: str
    status: str
    details: str
    data: Optional[dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "module": self.module,
            "status": self.status,
            "details": self.details,
            "data": self.data or {},
            "timestamp": self.timestamp,
            "error": self.error,
        }


class PostModule(ABC):
    """
    Abstract base class for post-exploitation modules.

    Post-exploitation modules are used after initial compromise to:
    - Establish persistence
    - Escalate privileges
    - Move laterally
    - Exfiltrate data
    - Maintain access
    """

    MODULE_NAME: str = "base"
    MODULE_DESCRIPTION: str = "Base post-exploitation module"

    @abstractmethod
    def run(self, session: Any, **kwargs: Any) -> PostResult:
        """
        Execute the post-exploitation module.

        Args:
            session: Active session (could be JenkinsSession or shell session)
            **kwargs: Additional module-specific parameters

        Returns:
            PostResult: Result of module execution
        """
        pass

    def validate_params(self, **kwargs: Any) -> bool:
        """
        Validate required parameters for the module.

        Args:
            **kwargs: Parameters to validate

        Returns:
            bool: True if parameters are valid
        """
        return True

    def cleanup(self, session: Any, **kwargs: Any) -> bool:
        """
        Cleanup after module execution.

        Args:
            session: Active session
            **kwargs: Additional parameters

        Returns:
            bool: True if cleanup successful
        """
        return True
