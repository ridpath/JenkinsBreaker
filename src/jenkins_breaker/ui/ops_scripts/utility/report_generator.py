"""Red team report generator script."""

from ..base import OperatorScript, ScriptResult


class ReportGenerator(OperatorScript):
    """Red team report generator."""
    
    name = "Red Team Report Generator"
    description = "Red team report generator"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] RED TEAM REPORT GENERATOR"
echo "Executing Red team report generator..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Red team report generator...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Red team report generator executed",
                metadata={"script": "report_generator"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
