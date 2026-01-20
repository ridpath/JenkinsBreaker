"""Clipboard monitoring script."""

from ..base import OperatorScript, ScriptResult


class ClipboardMonitor(OperatorScript):
    """Clipboard monitoring."""
    
    name = "Clipboard Monitoring"
    description = "Clipboard monitoring"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CLIPBOARD MONITORING"
echo "Executing Clipboard monitoring..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Clipboard monitoring...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Clipboard monitoring executed",
                metadata={"script": "clipboard_monitor"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
