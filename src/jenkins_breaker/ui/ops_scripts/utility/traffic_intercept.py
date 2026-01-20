"""Traffic interception script."""

from ..base import OperatorScript, ScriptResult


class TrafficIntercept(OperatorScript):
    """Traffic interception."""
    
    name = "Traffic Interception"
    description = "Traffic interception"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] TRAFFIC INTERCEPTION"
echo "Executing Traffic interception..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Traffic interception...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Traffic interception executed",
                metadata={"script": "traffic_intercept"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
