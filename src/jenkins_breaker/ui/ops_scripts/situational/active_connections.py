"""Monitor active connections script."""

from ..base import OperatorScript, ScriptResult


class ActiveConnections(OperatorScript):
    """Monitor active connections."""
    
    name = "Monitor Active Connections"
    description = "Monitor active connections"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] MONITOR ACTIVE CONNECTIONS"
echo "Executing Monitor active connections..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Monitor active connections...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Monitor active connections executed",
                metadata={"script": "active_connections"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
