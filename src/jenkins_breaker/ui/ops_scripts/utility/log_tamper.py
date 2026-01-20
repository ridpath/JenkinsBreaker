"""Log tampering tools script."""

from ..base import OperatorScript, ScriptResult


class LogTamper(OperatorScript):
    """Log tampering tools."""
    
    name = "Log Tampering Tools"
    description = "Log tampering tools"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] LOG TAMPERING TOOLS"
echo "Executing Log tampering tools..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Log tampering tools...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Log tampering tools executed",
                metadata={"script": "log_tamper"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
