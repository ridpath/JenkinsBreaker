"""Terraform variable files script."""

from ..base import OperatorScript, ScriptResult


class TerraformVars(OperatorScript):
    """Terraform variable files."""
    
    name = "Terraform Variable Files"
    description = "Terraform variable files"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] TERRAFORM VARIABLE FILES"
echo "Executing Terraform variable files..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Terraform variable files...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Terraform variable files executed",
                metadata={"script": "terraform_vars"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
