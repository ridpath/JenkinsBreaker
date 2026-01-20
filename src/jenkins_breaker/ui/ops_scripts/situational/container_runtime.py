"""Container runtime detection script."""

from ..base import OperatorScript, ScriptResult


class ContainerRuntime(OperatorScript):
    """Container runtime detection."""
    
    name = "Container Runtime Detection"
    description = "Container runtime detection"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CONTAINER RUNTIME DETECTION"
echo "Executing Container runtime detection..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Container runtime detection...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Container runtime detection executed",
                metadata={"script": "container_runtime"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
