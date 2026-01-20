"""Capabilities enumeration script."""

from ..base import OperatorScript, ScriptResult


class CapabilitiesEnum(OperatorScript):
    """List dangerous Linux capabilities."""
    
    name = "Capabilities Enumeration"
    description = "Enumerate Linux capabilities for privilege escalation"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CAPABILITY ENUMERATION"
echo "========================="
echo ""

echo "[+] Binaries with capabilities:"
which getcap >/dev/null 2>&1 && {
    getcap -r / 2>/dev/null | while read line; do
        echo "[!] $line"
    done
} || echo "[-] getcap not found"
echo ""

echo "[*] Process capabilities:"
cat /proc/self/status | grep Cap
echo ""

echo "[*] Dangerous capabilities to look for:"
echo "  cap_setuid - can change UID (instant root)"
echo "  cap_sys_admin - mount, privileged operations"
echo "  cap_dac_override - bypass file permissions"
echo "  cap_net_raw - packet capture, spoofing"
echo "  cap_sys_ptrace - inject into processes"
echo ""

echo "[*] Current process capabilities decoded:"
cat /proc/self/status | grep CapEff
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating capabilities...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Capabilities enumeration executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
