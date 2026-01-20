"""Azure blob storage access script."""

from ..base import OperatorScript, ScriptResult


class AzureBlob(OperatorScript):
    """Azure blob storage access."""
    
    name = "Azure Blob Storage Access"
    description = "Azure blob storage access"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AZURE BLOB STORAGE ACCESS"
echo "Executing Azure blob storage access..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Azure blob storage access...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Azure blob storage access executed",
                metadata={"script": "azure_blob"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
