"""Syslog destination discovery script."""

from ..base import OperatorScript, ScriptResult


class SyslogDestination(OperatorScript):
    """Syslog destination discovery."""
    
    name = "Syslog Destination Discovery"
    description = "Syslog destination discovery"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SYSLOG DESTINATION DISCOVERY"
echo "Executing Syslog destination discovery..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Syslog destination discovery...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Syslog destination discovery executed",
                metadata={"script": "syslog_destination"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
