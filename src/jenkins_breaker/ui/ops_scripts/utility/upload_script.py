"""Upload custom script script."""

from ..base import OperatorScript, ScriptResult


class UploadScript(OperatorScript):
    """Upload custom script."""
    
    name = "Upload Custom Script"
    description = "Upload custom script"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] UPLOAD CUSTOM SCRIPT"
echo "Executing Upload custom script..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Upload custom script...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Upload custom script executed",
                metadata={"script": "upload_script"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
