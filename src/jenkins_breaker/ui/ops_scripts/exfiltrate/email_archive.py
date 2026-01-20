"""Email archive extraction script."""

from ..base import OperatorScript, ScriptResult


class EmailArchive(OperatorScript):
    """Email archive extraction."""
    
    name = "Email Archive Extraction"
    description = "Email archive extraction"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] EMAIL ARCHIVE EXTRACTION"
echo "Executing Email archive extraction..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Email archive extraction...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Email archive extraction executed",
                metadata={"script": "email_archive"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
