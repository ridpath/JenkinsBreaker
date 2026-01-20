"""SSL/TLS certificates script."""

from ..base import OperatorScript, ScriptResult


class CertificateHarvest(OperatorScript):
    """SSL/TLS certificates."""
    
    name = "Ssl/Tls Certificates"
    description = "SSL/TLS certificates"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SSL/TLS CERTIFICATES"
echo "Executing SSL/TLS certificates..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running SSL/TLS certificates...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SSL/TLS certificates executed",
                metadata={"script": "certificate_harvest"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
