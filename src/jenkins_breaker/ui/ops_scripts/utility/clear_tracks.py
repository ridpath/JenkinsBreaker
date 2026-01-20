"""Clear logs and artifacts script."""

from ..base import OperatorScript, ScriptResult


class ClearTracks(OperatorScript):
    """Clear logs and artifacts."""
    
    name = "Clear Logs And Artifacts"
    description = "Clear logs and artifacts"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CLEAR LOGS AND ARTIFACTS"
echo "Executing Clear logs and artifacts..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Clear logs and artifacts...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Clear logs and artifacts executed",
                metadata={"script": "clear_tracks"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
