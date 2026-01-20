"""Extract Kerberos tickets script."""

from ..base import OperatorScript, ScriptResult


class KerberosTickets(OperatorScript):
    """Extract Kerberos tickets."""
    
    name = "Extract Kerberos Tickets"
    description = "Extract Kerberos tickets"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] EXTRACT KERBEROS TICKETS"
echo "Executing Extract Kerberos tickets..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Extract Kerberos tickets...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Extract Kerberos tickets executed",
                metadata={"script": "kerberos_tickets"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
