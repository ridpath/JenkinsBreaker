"""Full environment context script."""

from ..base import OperatorScript, ScriptResult


class EnvironmentContext(OperatorScript):
    """Full environment context."""
    
    name = "Full Environment Context"
    description = "Full environment context"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] FULL ENVIRONMENT CONTEXT"
echo "Executing Full environment context..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Full environment context...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Full environment context executed",
                metadata={"script": "environment_context"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
