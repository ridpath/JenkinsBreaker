"""File search by extension script."""

from ..base import OperatorScript, ScriptResult


class FileSearch(OperatorScript):
    """File search by extension."""
    
    name = "File Search By Extension"
    description = "File search by extension"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] FILE SEARCH BY EXTENSION"
echo "Executing File search by extension..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running File search by extension...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="File search by extension executed",
                metadata={"script": "file_search"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
