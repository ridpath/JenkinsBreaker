"""Anti-forensics suite script."""

from ..base import OperatorScript, ScriptResult


class AntiForensics(OperatorScript):
    """Anti-forensics suite."""
    
    name = "Anti-Forensics Suite"
    description = "Anti-forensics suite"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ANTI-FORENSICS SUITE"
echo "Executing Anti-forensics suite..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Anti-forensics suite...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Anti-forensics suite executed",
                metadata={"script": "anti_forensics"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
