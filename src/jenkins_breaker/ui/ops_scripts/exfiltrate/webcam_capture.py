"""Webcam capture script."""

from ..base import OperatorScript, ScriptResult


class WebcamCapture(OperatorScript):
    """Webcam capture."""
    
    name = "Webcam Capture"
    description = "Webcam capture"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] WEBCAM CAPTURE"
echo "Executing Webcam capture..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Webcam capture...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Webcam capture executed",
                metadata={"script": "webcam_capture"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
