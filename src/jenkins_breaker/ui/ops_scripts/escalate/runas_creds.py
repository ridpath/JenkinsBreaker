"""Extract RunAs credentials script."""

from ..base import OperatorScript, ScriptResult


class RunAsCreds(OperatorScript):
    """Extract RunAs credentials."""
    
    name = "Extract Runas Credentials"
    description = "Extract RunAs credentials"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] EXTRACT RUNAS CREDENTIALS"
echo "Executing Extract RunAs credentials..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Extract RunAs credentials...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Extract RunAs credentials executed",
                metadata={"script": "runas_creds"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
