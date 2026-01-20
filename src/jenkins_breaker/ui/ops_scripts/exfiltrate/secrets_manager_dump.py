"""Secrets manager dump script."""

from ..base import OperatorScript, ScriptResult


class SecretsManagerDump(OperatorScript):
    """Secrets manager dump."""
    
    name = "Secrets Manager Dump"
    description = "Secrets manager dump"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SECRETS MANAGER DUMP"
echo "Executing Secrets manager dump..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Secrets manager dump...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Secrets manager dump executed",
                metadata={"script": "secrets_manager_dump"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
