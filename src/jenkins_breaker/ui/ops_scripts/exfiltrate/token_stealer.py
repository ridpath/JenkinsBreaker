"""K8s/Docker/Cloud tokens script."""

from ..base import OperatorScript, ScriptResult


class TokenStealer(OperatorScript):
    """K8s/Docker/Cloud tokens."""
    
    name = "K8S/Docker/Cloud Tokens"
    description = "K8s/Docker/Cloud tokens"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] K8S/DOCKER/CLOUD TOKENS"
echo "Executing K8s/Docker/Cloud tokens..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running K8s/Docker/Cloud tokens...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="K8s/Docker/Cloud tokens executed",
                metadata={"script": "token_stealer"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
