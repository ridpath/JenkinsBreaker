"""Grab SAM/SYSTEM files script."""

from ..base import OperatorScript, ScriptResult


class SAMSystemGrab(OperatorScript):
    """Grab SAM/SYSTEM files."""
    
    name = "Grab Sam/System Files"
    description = "Grab SAM/SYSTEM files"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] GRAB SAM/SYSTEM FILES"
echo "Executing Grab SAM/SYSTEM files..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Grab SAM/SYSTEM files...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Grab SAM/SYSTEM files executed",
                metadata={"script": "sam_system_grab"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
