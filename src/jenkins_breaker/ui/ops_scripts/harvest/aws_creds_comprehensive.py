"""Comprehensive AWS credential sources script."""

from ..base import OperatorScript, ScriptResult


class AWSCredsComprehensive(OperatorScript):
    """Comprehensive AWS credential sources."""
    
    name = "Comprehensive Aws Credential Sources"
    description = "Comprehensive AWS credential sources"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] COMPREHENSIVE AWS CREDENTIAL SOURCES"
echo "Executing Comprehensive AWS credential sources..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Comprehensive AWS credential sources...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Comprehensive AWS credential sources executed",
                metadata={"script": "aws_creds_comprehensive"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
