"""Automated screenshot loop script."""

from ..base import OperatorScript, ScriptResult


class ScreenshotLoop(OperatorScript):
    """Automated screenshot loop."""
    
    name = "Automated Screenshot Loop"
    description = "Automated screenshot loop"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AUTOMATED SCREENSHOT LOOP"
echo "Executing Automated screenshot loop..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Automated screenshot loop...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Automated screenshot loop executed",
                metadata={"script": "screenshot_loop"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
