"""Chisel tunnel setup script."""

from ..base import OperatorScript, ScriptResult


class ChiselTunnel(OperatorScript):
    """Chisel tunnel setup."""
    
    name = "Chisel Tunnel Setup"
    description = "Chisel tunnel setup"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CHISEL TUNNEL SETUP"
echo "Executing Chisel tunnel setup..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Chisel tunnel setup...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Chisel tunnel setup executed",
                metadata={"script": "chisel_tunnel"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
