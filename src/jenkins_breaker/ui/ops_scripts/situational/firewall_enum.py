"""Enumerate firewall rules script."""

from ..base import OperatorScript, ScriptResult


class FirewallEnum(OperatorScript):
    """Enumerate firewall rules."""
    
    name = "Enumerate Firewall Rules"
    description = "Enumerate firewall rules"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ENUMERATE FIREWALL RULES"
echo "Executing Enumerate firewall rules..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Enumerate firewall rules...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Enumerate firewall rules executed",
                metadata={"script": "firewall_enum"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
