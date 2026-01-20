"""Remove all persistence script."""

from ..base import OperatorScript, ScriptResult


class CleanupTool(OperatorScript):
    """Remove all persistence."""
    
    name = "Remove All Persistence"
    description = "Remove all persistence"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] REMOVE ALL PERSISTENCE"
echo "Executing Remove all persistence..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Remove all persistence...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Remove all persistence executed",
                metadata={"script": "cleanup_tool"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
