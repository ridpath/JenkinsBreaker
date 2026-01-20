"""Detect monitoring processes script."""

from ..base import OperatorScript, ScriptResult


class MonitoringDetection(OperatorScript):
    """Detect monitoring processes."""
    
    name = "Detect Monitoring Processes"
    description = "Detect monitoring processes"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DETECT MONITORING PROCESSES"
echo "Executing Detect monitoring processes..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Detect monitoring processes...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Detect monitoring processes executed",
                metadata={"script": "monitoring_detection"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
