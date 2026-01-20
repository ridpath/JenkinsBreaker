"""/etc/shadow extraction script."""

from ..base import OperatorScript, ScriptResult


class ShadowExtract(OperatorScript):
    """/etc/shadow extraction."""
    
    name = "/Etc/Shadow Extraction"
    description = "/etc/shadow extraction"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] /ETC/SHADOW EXTRACTION"
echo "Executing /etc/shadow extraction..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running /etc/shadow extraction...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="/etc/shadow extraction executed",
                metadata={"script": "shadow_extract"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
