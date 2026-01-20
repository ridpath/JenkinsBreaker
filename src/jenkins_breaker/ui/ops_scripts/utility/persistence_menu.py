"""Persistence installer menu script."""

from ..base import OperatorScript, ScriptResult


class PersistenceMenu(OperatorScript):
    """Persistence installer menu."""
    
    name = "Persistence Installer Menu"
    description = "Persistence installer menu"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PERSISTENCE INSTALLER MENU"
echo "Executing Persistence installer menu..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Persistence installer menu...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Persistence installer menu executed",
                metadata={"script": "persistence_menu"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
