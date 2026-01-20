"""SOCKS proxy setup script."""

from ..base import OperatorScript, ScriptResult


class SOCKSProxy(OperatorScript):
    """SOCKS proxy setup."""
    
    name = "Socks Proxy Setup"
    description = "SOCKS proxy setup"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SOCKS PROXY SETUP"
echo "Executing SOCKS proxy setup..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running SOCKS proxy setup...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SOCKS proxy setup executed",
                metadata={"script": "socks_proxy"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
