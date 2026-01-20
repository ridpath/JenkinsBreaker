"""Sudo version checker for CVE mapping."""

from ..base import OperatorScript, ScriptResult


class SudoVersionCheck(OperatorScript):
    """Check sudo version against CVE database."""
    
    name = "Sudo Exploit Checker"
    description = "Check sudo version for known vulnerabilities"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SUDO EXPLOIT CHECKER"
echo "======================="
echo ""

which sudo >/dev/null 2>&1 || {
    echo "[-] sudo not installed"
    exit 0
}

echo "[+] Sudo version:"
sudo -V 2>/dev/null | head -3
SUDO_VER=$(sudo -V 2>/dev/null | head -1 | grep -oP '\\d+\\.\\d+\\.\\d+')
echo ""

echo "[*] Known vulnerabilities:"
echo "  CVE-2021-3156 (Baron Samedit): sudo < 1.9.5p2"
echo "  CVE-2019-14287: sudo < 1.8.28 (bypass with -u#-1)"
echo "  CVE-2019-18634: sudo < 1.8.26 (pwfeedback buffer overflow)"
echo ""

echo "[+] Sudo permissions:"
sudo -l 2>/dev/null || echo "[-] Cannot list sudo permissions"
echo ""

echo "[*] Sudo config files:"
ls -la /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/ 2>/dev/null
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Checking sudo version...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Sudo version check executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
