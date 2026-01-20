"""Browser history exfiltration script."""

from ..base import OperatorScript, ScriptResult


class BrowserHistory(OperatorScript):
    """Browser history exfiltration."""
    
    name = "Browser History Exfiltration"
    description = "Browser history exfiltration"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] BROWSER HISTORY EXFILTRATION"
echo "Executing Browser history exfiltration..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Browser history exfiltration...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Browser history exfiltration executed",
                metadata={"script": "browser_history"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
