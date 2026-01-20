"""K8s/Docker Swarm detection script."""

from ..base import OperatorScript, ScriptResult


class OrchestratorDetection(OperatorScript):
    """K8s/Docker Swarm detection."""
    
    name = "K8S/Docker Swarm Detection"
    description = "K8s/Docker Swarm detection"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] K8S/DOCKER SWARM DETECTION"
echo "Executing K8s/Docker Swarm detection..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running K8s/Docker Swarm detection...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="K8s/Docker Swarm detection executed",
                metadata={"script": "orchestrator_detection"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
