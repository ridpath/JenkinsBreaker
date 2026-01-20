"""K8s service account tokens script."""

from ..base import OperatorScript, ScriptResult


class KubernetesTokens(OperatorScript):
    """K8s service account tokens."""
    
    name = "K8S Service Account Tokens"
    description = "K8s service account tokens"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] K8S SERVICE ACCOUNT TOKENS"
echo "Executing K8s service account tokens..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running K8s service account tokens...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="K8s service account tokens executed",
                metadata={"script": "kubernetes_tokens"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
