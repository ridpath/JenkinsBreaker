"""Antivirus exclusion discovery script."""

from ..base import OperatorScript, ScriptResult


class AVExclusions(OperatorScript):
    """Antivirus exclusion discovery."""
    
    name = "Antivirus Exclusion Discovery"
    description = "Antivirus exclusion discovery"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ANTIVIRUS EXCLUSION DISCOVERY"
echo "Executing Antivirus exclusion discovery..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Antivirus exclusion discovery...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Antivirus exclusion discovery executed",
                metadata={"script": "av_exclusions"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
