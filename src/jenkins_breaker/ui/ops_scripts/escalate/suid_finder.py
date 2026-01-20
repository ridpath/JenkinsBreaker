"""SUID binary finder and GTFOBins analyzer."""

from ..base import OperatorScript, ScriptResult


class SuidFinder(OperatorScript):
    """Find and categorize SUID/SGID binaries with GTFOBins checks."""
    
    name = "SUID/SGID Finder"
    description = "Find and categorize SUID/SGID binaries with exploitation paths"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SUID/SGID BINARY HUNTER"
echo "==========================="
echo ""

echo "[+] SUID binaries (perm -4000):"
find / -perm -4000 -type f 2>/dev/null | while read file; do
    ls -lah "$file"
done
echo ""

echo "[+] SGID binaries (perm -2000):"
find / -perm -2000 -type f 2>/dev/null | head -20
echo ""

echo "[*] HIGH-VALUE SUID/SGID TARGETS:"
echo ""
echo "GTFOBins exploitable:"
find / -perm -6000 -type f 2>/dev/null | grep -E "(nmap|vim|find|bash|more|less|nano|cp|mv|awk|python|perl|ruby|lua|php|tclsh|expect|rpm|dpkg)" | while read file; do
    echo "[!] EXPLOITABLE: $file"
done
echo ""

echo "[*] Writable SUID binaries (rare but instant root):"
find / -perm -4000 -type f -writable 2>/dev/null
echo ""

echo "[*] Custom SUID binaries (not in /usr/bin, /bin):"
find / -perm -4000 -type f 2>/dev/null | grep -v "/usr/bin/" | grep -v "/bin/" | head -20
echo ""

echo "[*] SUID owned by non-root:"
find / -perm -4000 -type f ! -user root 2>/dev/null
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Scanning for SUID/SGID binaries...[/bold cyan]")
            
            payload = self.get_payload()
            
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SUID finder executed",
                metadata={"script": "suid_finder"}
            )
        except Exception as e:
            return ScriptResult(
                success=False,
                output="",
                error=str(e)
            )
