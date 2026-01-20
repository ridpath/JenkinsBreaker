"""GCP service account keys script."""

from ..base import OperatorScript, ScriptResult


class GCPServiceAccounts(OperatorScript):
    """GCP service account keys."""
    
    name = "Gcp Service Account Keys"
    description = "GCP service account keys"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] GCP SERVICE ACCOUNT KEYS"
echo "Executing GCP service account keys..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running GCP service account keys...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="GCP service account keys executed",
                metadata={"script": "gcp_service_accounts"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
