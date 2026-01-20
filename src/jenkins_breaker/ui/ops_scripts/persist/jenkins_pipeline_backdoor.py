"""Jenkins pipeline backdoor script."""
from ..base import OperatorScript, ScriptResult

class JenkinsPipelineBackdoor(OperatorScript):
    name = "Jenkins Pipeline Backdoor"
    description = "Jenkins pipeline persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] JENKINS PIPELINE BACKDOOR"
echo "Create Jenkinsfile with malicious pipeline stage"
echo "Executes on every build"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Jenkins pipeline backdoor...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Jenkins pipeline backdoor executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
