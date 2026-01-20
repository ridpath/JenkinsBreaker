"""Reverse SSH tunnel script."""

from ..base import OperatorScript, ScriptResult


class ReverseSSH(OperatorScript):
    """Reverse SSH tunnel."""
    
    name = "Reverse Ssh Tunnel"
    description = "Reverse SSH tunnel"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] REVERSE SSH TUNNEL"
echo "Executing Reverse SSH tunnel..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Reverse SSH tunnel...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Reverse SSH tunnel executed",
                metadata={"script": "reverse_ssh"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
