"""Windows weak service permissions script."""

from ..base import OperatorScript, ScriptResult


class WeakServicePermissions(OperatorScript):
    """Windows weak service permissions."""
    
    name = "Windows Weak Service Permissions"
    description = "Windows weak service permissions"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] WINDOWS WEAK SERVICE PERMISSIONS"
echo "Executing Windows weak service permissions..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Windows weak service permissions...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Windows weak service permissions executed",
                metadata={"script": "weak_service_permissions"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
