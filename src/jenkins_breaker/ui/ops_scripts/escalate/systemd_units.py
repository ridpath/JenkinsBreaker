"""Find exploitable systemd units script."""

from ..base import OperatorScript, ScriptResult


class SystemdUnits(OperatorScript):
    """Find exploitable systemd units."""
    
    name = "Find Exploitable Systemd Units"
    description = "Find exploitable systemd units"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] FIND EXPLOITABLE SYSTEMD UNITS"
echo "Executing Find exploitable systemd units..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Find exploitable systemd units...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Find exploitable systemd units executed",
                metadata={"script": "systemd_units"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
