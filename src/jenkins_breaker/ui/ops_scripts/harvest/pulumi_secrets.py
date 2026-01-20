"""Pulumi secret values script."""

from ..base import OperatorScript, ScriptResult


class PulumiSecrets(OperatorScript):
    """Pulumi secret values."""
    
    name = "Pulumi Secret Values"
    description = "Pulumi secret values"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PULUMI SECRET VALUES"
echo "Executing Pulumi secret values..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Pulumi secret values...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Pulumi secret values executed",
                metadata={"script": "pulumi_secrets"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
