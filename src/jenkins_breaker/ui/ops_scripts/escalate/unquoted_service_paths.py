"""Unquoted service path exploitation script."""

from ..base import OperatorScript, ScriptResult


class UnquotedServicePaths(OperatorScript):
    """Unquoted service path exploitation."""
    
    name = "Unquoted Service Path Exploitation"
    description = "Unquoted service path exploitation"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] UNQUOTED SERVICE PATH EXPLOITATION"
echo "Executing Unquoted service path exploitation..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Unquoted service path exploitation...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Unquoted service path exploitation executed",
                metadata={"script": "unquoted_service_paths"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
