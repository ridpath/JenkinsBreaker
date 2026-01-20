"""Database dump and compress script."""

from ..base import OperatorScript, ScriptResult


class DatabaseDump(OperatorScript):
    """Database dump and compress."""
    
    name = "Database Dump And Compress"
    description = "Database dump and compress"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DATABASE DUMP AND COMPRESS"
echo "Executing Database dump and compress..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Database dump and compress...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Database dump and compress executed",
                metadata={"script": "database_dump"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
