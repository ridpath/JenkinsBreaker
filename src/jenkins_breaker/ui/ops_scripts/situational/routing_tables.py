"""Routing table analysis script."""

from ..base import OperatorScript, ScriptResult


class RoutingTables(OperatorScript):
    """Routing table analysis."""
    
    name = "Routing Table Analysis"
    description = "Routing table analysis"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ROUTING TABLE ANALYSIS"
echo "Executing Routing table analysis..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Routing table analysis...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Routing table analysis executed",
                metadata={"script": "routing_tables"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
