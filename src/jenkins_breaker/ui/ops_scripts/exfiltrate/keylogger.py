"""Keylogger deployment script."""

from ..base import OperatorScript, ScriptResult


class Keylogger(OperatorScript):
    """Keylogger deployment."""
    
    name = "Keylogger Deployment"
    description = "Keylogger deployment"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] KEYLOGGER DEPLOYMENT"
echo "Executing Keylogger deployment..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Keylogger deployment...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Keylogger deployment executed",
                metadata={"script": "keylogger"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
