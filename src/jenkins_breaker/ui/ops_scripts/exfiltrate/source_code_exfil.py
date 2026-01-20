"""Repository exfiltration script."""

from ..base import OperatorScript, ScriptResult


class SourceCodeExfil(OperatorScript):
    """Repository exfiltration."""
    
    name = "Repository Exfiltration"
    description = "Repository exfiltration"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] REPOSITORY EXFILTRATION"
echo "Executing Repository exfiltration..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Repository exfiltration...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Repository exfiltration executed",
                metadata={"script": "source_code_exfil"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
