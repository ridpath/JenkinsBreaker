"""Screenshot capture script."""

from ..base import OperatorScript, ScriptResult


class ScreenshotCapture(OperatorScript):
    """Screenshot capture."""
    
    name = "Screenshot Capture"
    description = "Screenshot capture"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SCREENSHOT CAPTURE"
echo "Executing Screenshot capture..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Screenshot capture...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Screenshot capture executed",
                metadata={"script": "screenshot_capture"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
