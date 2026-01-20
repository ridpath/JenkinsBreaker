"""Azure managed identity tokens script."""

from ..base import OperatorScript, ScriptResult


class AzureManagedIdentity(OperatorScript):
    """Azure managed identity tokens."""
    
    name = "Azure Managed Identity Tokens"
    description = "Azure managed identity tokens"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AZURE MANAGED IDENTITY TOKENS"
echo "Executing Azure managed identity tokens..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Azure managed identity tokens...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Azure managed identity tokens executed",
                metadata={"script": "azure_managed_identity"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
