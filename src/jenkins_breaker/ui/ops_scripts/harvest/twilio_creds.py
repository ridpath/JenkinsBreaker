"""Twilio credentials script."""

from ..base import OperatorScript, ScriptResult


class TwilioCreds(OperatorScript):
    """Twilio credentials."""
    
    name = "Twilio Credentials"
    description = "Twilio credentials"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] TWILIO CREDENTIALS"
echo "Executing Twilio credentials..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Twilio credentials...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Twilio credentials executed",
                metadata={"script": "twilio_creds"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
