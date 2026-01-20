"""ARP cache analysis and scanning script."""

from ..base import OperatorScript, ScriptResult


class ARPScan(OperatorScript):
    """ARP cache parsing with integrated port scanning."""
    
    name = "ARP Scan"
    description = "ARP cache parsing with integrated port scanning"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ARP CACHE SCAN"
echo "================="
echo ""

echo "[+] Current ARP cache:"
if command -v ip &>/dev/null; then
    ip neigh show
else
    arp -a
fi
echo ""

echo "[+] Network interfaces and IPs:"
if command -v ip &>/dev/null; then
    ip addr show | grep -E "inet |ether "
else
    ifconfig | grep -E "inet |ether "
fi
echo ""

echo "[+] MAC address vendors:"
ip neigh show 2>/dev/null | awk '{print $5}' | while read mac; do
    if [ ! -z "$mac" ]; then
        OUI=$(echo $mac | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
        echo "$mac -> Vendor lookup: $OUI"
    fi
done
echo ""

echo "[+] Scanning ARP cache hosts for common ports..."
ip neigh show 2>/dev/null | awk '{print $1}' | while read host; do
    if [ ! -z "$host" ] && [[ ! "$host" =~ "fe80" ]]; then
        echo "[*] Scanning $host"
        for port in 22 80 443 445 3389 8080; do
            timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && \
                echo "  [+] $host:$port OPEN"
        done
    fi
done
echo ""

echo "[+] Broadcasting ARP request to discover hidden hosts:"
if command -v arping &>/dev/null; then
    LOCAL_NET=$(ip route | grep default | awk '{print $3}' | cut -d. -f1-3)
    echo "[*] Scanning ${LOCAL_NET}.0/24"
    for i in {1..10}; do
        arping -c 1 -I eth0 ${LOCAL_NET}.$i 2>/dev/null &
    done
    wait
else
    echo "[-] arping not available"
fi
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running ARP scan...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="ARP scan executed",
                metadata={"script": "arp_scan"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
