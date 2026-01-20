"""SSH tunnel automation script."""

from ..base import OperatorScript, ScriptResult


class SSHTunnel(OperatorScript):
    """SSH tunnel automation."""
    
    name = "Ssh Tunnel Automation"
    description = "SSH tunnel automation"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SSH TUNNEL AUTOMATION"
echo "Executing SSH tunnel automation..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running SSH tunnel automation...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SSH tunnel automation executed",
                metadata={"script": "ssh_tunnel"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
