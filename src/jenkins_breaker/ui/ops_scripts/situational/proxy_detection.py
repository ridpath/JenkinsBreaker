"""Proxy detection script."""

from ..base import OperatorScript, ScriptResult


class ProxyDetection(OperatorScript):
    """Proxy detection."""
    
    name = "Proxy Detection"
    description = "Proxy detection"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PROXY DETECTION"
echo "Executing Proxy detection..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Proxy detection...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Proxy detection executed",
                metadata={"script": "proxy_detection"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
