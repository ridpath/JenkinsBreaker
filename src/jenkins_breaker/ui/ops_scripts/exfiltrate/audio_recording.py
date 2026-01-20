"""Audio recording script."""

from ..base import OperatorScript, ScriptResult


class AudioRecording(OperatorScript):
    """Audio recording."""
    
    name = "Audio Recording"
    description = "Audio recording"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] AUDIO RECORDING"
echo "Executing Audio recording..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Audio recording...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Audio recording executed",
                metadata={"script": "audio_recording"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
