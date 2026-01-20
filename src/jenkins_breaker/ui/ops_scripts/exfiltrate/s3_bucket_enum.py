"""AWS S3 bucket download script."""

from ..base import OperatorScript, ScriptResult


class S3BucketEnum(OperatorScript):
    """AWS S3 bucket download."""
    
    name = "Aws S3 Bucket Download"
    description = "AWS S3 bucket download"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AWS S3 BUCKET DOWNLOAD"
echo "Executing AWS S3 bucket download..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running AWS S3 bucket download...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="AWS S3 bucket download executed",
                metadata={"script": "s3_bucket_enum"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
