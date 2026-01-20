"""Process injection helper script."""

from ..base import OperatorScript, ScriptResult


class ProcessInjection(OperatorScript):
    """Process injection helper."""
    
    name = "Process Injection Helper"
    description = "Process injection helper"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PROCESS INJECTION HELPER"
echo "Executing Process injection helper..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Process injection helper...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Process injection helper executed",
                metadata={"script": "process_injection"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
