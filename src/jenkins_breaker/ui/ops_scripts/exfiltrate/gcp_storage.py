"""GCP storage bucket access script."""

from ..base import OperatorScript, ScriptResult


class GCPStorage(OperatorScript):
    """GCP storage bucket access."""
    
    name = "Gcp Storage Bucket Access"
    description = "GCP storage bucket access"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] GCP STORAGE BUCKET ACCESS"
echo "Executing GCP storage bucket access..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running GCP storage bucket access...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="GCP storage bucket access executed",
                metadata={"script": "gcp_storage"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
