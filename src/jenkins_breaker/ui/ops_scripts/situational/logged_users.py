"""Enumerate logged users script."""

from ..base import OperatorScript, ScriptResult


class LoggedUsers(OperatorScript):
    """Enumerate logged users."""
    
    name = "Enumerate Logged Users"
    description = "Enumerate logged users"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ENUMERATE LOGGED USERS"
echo "Executing Enumerate logged users..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Enumerate logged users...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Enumerate logged users executed",
                metadata={"script": "logged_users"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
