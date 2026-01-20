"""Docker registry credentials script."""

from ..base import OperatorScript, ScriptResult


class DockerRegistryCreds(OperatorScript):
    """Docker registry credentials."""
    
    name = "Docker Registry Credentials"
    description = "Docker registry credentials"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DOCKER REGISTRY CREDENTIALS"
echo "Executing Docker registry credentials..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Docker registry credentials...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Docker registry credentials executed",
                metadata={"script": "docker_registry_creds"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
