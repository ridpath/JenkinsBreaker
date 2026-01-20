"""Windows scheduled task exploitation script."""

from ..base import OperatorScript, ScriptResult


class ScheduledTaskHijack(OperatorScript):
    """Windows scheduled task exploitation."""
    
    name = "Windows Scheduled Task Exploitation"
    description = "Windows scheduled task exploitation"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] WINDOWS SCHEDULED TASK EXPLOITATION"
echo "Executing Windows scheduled task exploitation..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Windows scheduled task exploitation...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Windows scheduled task exploitation executed",
                metadata={"script": "scheduled_task_hijack"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
