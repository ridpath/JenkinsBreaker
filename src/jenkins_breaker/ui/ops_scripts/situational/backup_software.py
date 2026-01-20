"""Backup software detection script."""

from ..base import OperatorScript, ScriptResult


class BackupSoftware(OperatorScript):
    """Backup software detection."""
    
    name = "Backup Software Detection"
    description = "Backup software detection"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] BACKUP SOFTWARE DETECTION"
echo "Executing Backup software detection..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Backup software detection...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Backup software detection executed",
                metadata={"script": "backup_software"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
