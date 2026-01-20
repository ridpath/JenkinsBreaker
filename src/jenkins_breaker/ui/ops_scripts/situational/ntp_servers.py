"""NTP server enumeration script."""

from ..base import OperatorScript, ScriptResult


class NTPServers(OperatorScript):
    """NTP server enumeration."""
    
    name = "Ntp Server Enumeration"
    description = "NTP server enumeration"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] NTP SERVER ENUMERATION"
echo "Executing NTP server enumeration..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running NTP server enumeration...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="NTP server enumeration executed",
                metadata={"script": "ntp_servers"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
