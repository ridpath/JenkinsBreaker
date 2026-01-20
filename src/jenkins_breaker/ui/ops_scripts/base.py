"""Base class for operator scripts."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class ScriptResult:
    """Result from executing an operator script."""
    
    success: bool
    output: str
    loot: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class OperatorScript(ABC):
    """Base class for all operator scripts."""
    
    name: str = "Unnamed Script"
    description: str = "No description"
    category: str = "utility"
    
    @abstractmethod
    def get_payload(self) -> str:
        """Return shell script or commands to run.
        
        Returns:
            Shell script content as string
        """
        pass
    
    @abstractmethod
    def run(
        self,
        session_meta: Any,
        send_command_func: Callable,
        output_func: Callable
    ) -> ScriptResult:
        """Execute the operator script.
        
        Args:
            session_meta: Session metadata object
            send_command_func: Function to send commands to target
            output_func: Function to output results to UI
            
        Returns:
            ScriptResult object with success status and output
        """
        pass
    
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse raw shell output into structured data.
        
        Override this method to provide custom parsing logic.
        
        Args:
            raw_output: Raw output from command execution
            
        Returns:
            Parsed data dictionary
        """
        return {"raw": raw_output}
