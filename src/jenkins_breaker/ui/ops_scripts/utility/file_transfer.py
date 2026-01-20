"""File upload/download manager script."""

from ..base import OperatorScript, ScriptResult


class FileTransfer(OperatorScript):
    """File upload/download manager."""
    
    name = "File Upload/Download Manager"
    description = "File upload/download manager"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] FILE UPLOAD/DOWNLOAD MANAGER"
echo "Executing File upload/download manager..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running File upload/download manager...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="File upload/download manager executed",
                metadata={"script": "file_transfer"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
