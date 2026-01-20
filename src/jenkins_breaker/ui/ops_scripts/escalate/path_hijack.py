"""PATH hijacking vulnerability detector."""

from ..base import OperatorScript, ScriptResult


class PathHijack(OperatorScript):
    """Find writable PATH directories for hijacking."""
    
    name = "PATH Hijack Detector"
    description = "Find writable directories in PATH for privilege escalation"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] WRITABLE PATH HIJACK DETECTOR"
echo "================================="
echo ""

echo "[+] Current PATH:"
echo "$PATH"
echo ""

echo "[*] Checking PATH directories for write access:"
echo "$PATH" | tr ':' '\\n' | while read dir; do
    if [ -d "$dir" ]; then
        if [ -w "$dir" ]; then
            echo "[!] WRITABLE: $dir"
        else
            echo "[ ] Not writable: $dir"
        fi
    else
        echo "[-] Does not exist: $dir"
    fi
done
echo ""

echo "[*] Writable system binary directories:"
for dir in /usr/local/bin /usr/bin /bin /usr/local/sbin /usr/sbin /sbin; do
    [ -w "$dir" ] && echo "[!] CRITICAL: $dir is writable"
done
echo ""

echo "[*] Scripts calling binaries without full path:"
find /usr/local/bin /usr/bin -type f 2>/dev/null | while read script; do
    if file "$script" | grep -q "shell script"; then
        grep -l "^[^/]*\\(ls\\|cat\\|ps\\|id\\)" "$script" 2>/dev/null && echo "[!] $script"
    fi
done | head -10
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Checking PATH for hijacking opportunities...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="PATH hijack check executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
