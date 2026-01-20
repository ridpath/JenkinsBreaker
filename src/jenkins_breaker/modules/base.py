"""
Base exploit module interface for JenkinsBreaker.

All exploit modules must inherit from ExploitModule and implement the required methods.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class ExploitMetadata:
    """Metadata for exploit modules."""

    cve_id: str
    name: str
    description: str
    affected_versions: list[str]
    mitre_attack: list[str]
    severity: str  # "critical", "high", "medium", "low"
    references: list[str] = field(default_factory=list)
    requires_auth: bool = True
    requires_crumb: bool = False
    tags: list[str] = field(default_factory=list)
    author: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            "cve_id": self.cve_id,
            "name": self.name,
            "description": self.description,
            "affected_versions": self.affected_versions,
            "mitre_attack": self.mitre_attack,
            "severity": self.severity,
            "references": self.references,
            "requires_auth": self.requires_auth,
            "requires_crumb": self.requires_crumb,
            "tags": self.tags,
            "author": self.author,
        }


@dataclass
class ExploitResult:
    """Result of exploit execution."""

    exploit: str
    status: str  # "success", "failure", "error", "skipped"
    details: str
    data: Optional[dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "exploit": self.exploit,
            "status": self.status,
            "details": self.details,
            "data": self.data or {},
            "timestamp": self.timestamp,
            "error": self.error,
        }


class ExploitModule(ABC):
    """
    Abstract base class for all exploit modules.

    Each exploit module must:
    - Define CVE_ID and METADATA class attributes
    - Implement check_vulnerable() method (optional, returns True by default)
    - Implement run() method with exploit logic
    - Optionally implement cleanup() for post-exploit cleanup

    Example:
        class CVE_2024_12345(ExploitModule):
            CVE_ID = "CVE-2024-12345"
            METADATA = ExploitMetadata(
                cve_id="CVE-2024-12345",
                name="Jenkins RCE",
                description="Remote code execution via Groovy script",
                affected_versions=["< 2.400"],
                mitre_attack=["T1059.006"],
                severity="critical",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
                requires_auth=True,
            )

            def check_vulnerable(self, session, **kwargs):
                return session.version < "2.400"

            def run(self, session, **kwargs):
                # Exploit logic here
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details="RCE achieved"
                )
    """

    CVE_ID: str = ""
    METADATA: ExploitMetadata = None

    @abstractmethod
    def run(self, session: Any, **kwargs) -> ExploitResult:
        """
        Execute the exploit.

        Args:
            session: JenkinsSession instance with authenticated session
            **kwargs: Additional arguments (lhost, lport, command, etc.)

        Returns:
            ExploitResult with status and details

        Raises:
            Exception: On critical errors (should be caught and returned as ExploitResult)
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement run() method")

    def check_vulnerable(self, session: Any, **kwargs) -> bool:
        """
        Optional vulnerability check before exploitation.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if target appears vulnerable, False otherwise
        """
        return True

    def cleanup(self, session: Any, **kwargs) -> None:
        """
        Optional cleanup after exploitation.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
        """
        pass

    def __repr__(self) -> str:
        """String representation of exploit module."""
        if self.METADATA:
            return f"<ExploitModule {self.CVE_ID}: {self.METADATA.name}>"
        return f"<ExploitModule {self.CVE_ID}>"


class ExploitRegistry:
    """
    Registry for dynamically loading and managing exploit modules.
    """

    def __init__(self) -> None:
        """Initialize the exploit registry."""
        self._modules: dict[str, ExploitModule] = {}
        self._metadata: dict[str, ExploitMetadata] = {}

    def register(self, module_class: type) -> None:
        """
        Register an exploit module.

        Args:
            module_class: Class inheriting from ExploitModule
        """
        if not issubclass(module_class, ExploitModule):
            raise TypeError(f"{module_class} must inherit from ExploitModule")

        if not module_class.CVE_ID:
            raise ValueError(f"{module_class} must define CVE_ID")

        if not module_class.METADATA:
            raise ValueError(f"{module_class} must define METADATA")

        instance = module_class()
        self._modules[module_class.CVE_ID] = instance
        self._metadata[module_class.CVE_ID] = module_class.METADATA

    def get(self, cve_id: str) -> Optional[ExploitModule]:
        """Get exploit module by CVE ID."""
        return self._modules.get(cve_id)

    def list_cves(self) -> list[str]:
        """List all registered CVE IDs."""
        return sorted(self._modules.keys())

    def get_metadata(self, cve_id: str) -> Optional[ExploitMetadata]:
        """Get metadata for a CVE."""
        return self._metadata.get(cve_id)

    def list_all(self) -> dict[str, ExploitMetadata]:
        """Get all registered exploits with metadata."""
        return self._metadata.copy()

    def filter_by_severity(self, severity: str) -> dict[str, ExploitMetadata]:
        """Filter exploits by severity level."""
        return {
            cve: meta for cve, meta in self._metadata.items()
            if meta.severity.lower() == severity.lower()
        }

    def filter_by_auth(self, requires_auth: bool) -> dict[str, ExploitMetadata]:
        """Filter exploits by authentication requirement."""
        return {
            cve: meta for cve, meta in self._metadata.items()
            if meta.requires_auth == requires_auth
        }


# Global registry instance
exploit_registry = ExploitRegistry()
