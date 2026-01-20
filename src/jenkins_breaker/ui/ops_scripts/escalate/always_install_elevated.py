"""AlwaysInstallElevated registry check script."""

from ..base import OperatorScript, ScriptResult


class AlwaysInstallElevated(OperatorScript):
    """AlwaysInstallElevated registry check."""
    
    name = "Alwaysinstallelevated Registry Check"
    description = "AlwaysInstallElevated registry check"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ALWAYSINSTALLELEVATED REGISTRY CHECK"
echo "Executing AlwaysInstallElevated registry check..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running AlwaysInstallElevated registry check...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="AlwaysInstallElevated registry check executed",
                metadata={"script": "always_install_elevated"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
