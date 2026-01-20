"""Cloud provider detection script."""

from ..base import OperatorScript, ScriptResult


class CloudProviderDetect(OperatorScript):
    """Cloud provider detection."""
    
    name = "Cloud Provider Detection"
    description = "Cloud provider detection"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CLOUD PROVIDER DETECTION"
echo "Executing Cloud provider detection..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Cloud provider detection...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Cloud provider detection executed",
                metadata={"script": "cloud_provider_detect"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
