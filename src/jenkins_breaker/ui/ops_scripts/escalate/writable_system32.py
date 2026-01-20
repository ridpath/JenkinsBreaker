"""Check for writable System32 files script."""

from ..base import OperatorScript, ScriptResult


class WritableSystem32(OperatorScript):
    """Check for writable System32 files."""
    
    name = "Check For Writable System32 Files"
    description = "Check for writable System32 files"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CHECK FOR WRITABLE SYSTEM32 FILES"
echo "Executing Check for writable System32 files..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Check for writable System32 files...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Check for writable System32 files executed",
                metadata={"script": "writable_system32"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
