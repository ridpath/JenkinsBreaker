"""Kubernetes admission webhook backdoor."""
from ..base import OperatorScript, ScriptResult

class K8sAdmissionWebhook(OperatorScript):
    name = "K8s Admission Webhook"
    description = "Kubernetes admission webhook backdoor"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] KUBERNETES ADMISSION WEBHOOK BACKDOOR"
echo "Requires cluster-admin privileges"
echo "Creates ValidatingWebhookConfiguration with malicious webhook"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] K8s admission webhook...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="K8s admission webhook executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
