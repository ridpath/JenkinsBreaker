"""Port forwarding setup script."""

from ..base import OperatorScript, ScriptResult


class PortForward(OperatorScript):
    """Port forwarding setup."""
    
    name = "Port Forwarding Setup"
    description = "Port forwarding setup"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PORT FORWARDING SETUP"
echo "Executing Port forwarding setup..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Port forwarding setup...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Port forwarding setup executed",
                metadata={"script": "port_forward"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
