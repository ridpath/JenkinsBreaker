"""HashiCorp Vault tokens script."""

from ..base import OperatorScript, ScriptResult


class VaultTokens(OperatorScript):
    """HashiCorp Vault tokens."""
    
    name = "Hashicorp Vault Tokens"
    description = "HashiCorp Vault tokens"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] HASHICORP VAULT TOKENS"
echo "Executing HashiCorp Vault tokens..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running HashiCorp Vault tokens...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="HashiCorp Vault tokens executed",
                metadata={"script": "vault_tokens"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
