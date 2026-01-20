"""DLL hijacking opportunities script."""

from ..base import OperatorScript, ScriptResult


class DLLHijacking(OperatorScript):
    """DLL hijacking opportunities."""
    
    name = "Dll Hijacking Opportunities"
    description = "DLL hijacking opportunities"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DLL HIJACKING OPPORTUNITIES"
echo "Executing DLL hijacking opportunities..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running DLL hijacking opportunities...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="DLL hijacking opportunities executed",
                metadata={"script": "dll_hijacking"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
