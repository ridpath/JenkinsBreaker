"""DNS server identification script."""

from ..base import OperatorScript, ScriptResult


class DNSServers(OperatorScript):
    """DNS server identification."""
    
    name = "Dns Server Identification"
    description = "DNS server identification"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DNS SERVER IDENTIFICATION"
echo "Executing DNS server identification..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running DNS server identification...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="DNS server identification executed",
                metadata={"script": "dns_servers"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
