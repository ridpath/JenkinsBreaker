"""SendGrid API keys script."""

from ..base import OperatorScript, ScriptResult


class SendGridKeys(OperatorScript):
    """SendGrid API keys."""
    
    name = "Sendgrid Api Keys"
    description = "SendGrid API keys"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SENDGRID API KEYS"
echo "Executing SendGrid API keys..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running SendGrid API keys...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SendGrid API keys executed",
                metadata={"script": "sendgrid_keys"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
