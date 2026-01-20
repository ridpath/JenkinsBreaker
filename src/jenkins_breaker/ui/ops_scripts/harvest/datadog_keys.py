"""Datadog API keys script."""

from ..base import OperatorScript, ScriptResult


class DatadogKeys(OperatorScript):
    """Datadog API keys."""
    
    name = "Datadog Api Keys"
    description = "Datadog API keys"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DATADOG API KEYS"
echo "Executing Datadog API keys..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Datadog API keys...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Datadog API keys executed",
                metadata={"script": "datadog_keys"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
