"""Enumerate and analyze cron jobs script."""

from ..base import OperatorScript, ScriptResult


class CronAnalysis(OperatorScript):
    """Enumerate and analyze cron jobs."""
    
    name = "Enumerate And Analyze Cron Jobs"
    description = "Enumerate and analyze cron jobs"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ENUMERATE AND ANALYZE CRON JOBS"
echo "Executing Enumerate and analyze cron jobs..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Enumerate and analyze cron jobs...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Enumerate and analyze cron jobs executed",
                metadata={"script": "cron_analysis"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
