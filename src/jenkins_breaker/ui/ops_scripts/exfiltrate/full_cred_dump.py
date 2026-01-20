"""Comprehensive credential dump script."""

from ..base import OperatorScript, ScriptResult


class FullCredDump(OperatorScript):
    """Comprehensive credential dump."""
    
    name = "Comprehensive Credential Dump"
    description = "Comprehensive credential dump"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] COMPREHENSIVE CREDENTIAL DUMP"
echo "Executing Comprehensive credential dump..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Comprehensive credential dump...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Comprehensive credential dump executed",
                metadata={"script": "full_cred_dump"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
