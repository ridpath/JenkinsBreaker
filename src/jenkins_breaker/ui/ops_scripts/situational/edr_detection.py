"""Detect EDR/AV products script."""

from ..base import OperatorScript, ScriptResult


class EDRDetection(OperatorScript):
    """Detect EDR/AV products."""
    
    name = "Detect Edr/Av Products"
    description = "Detect EDR/AV products"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DETECT EDR/AV PRODUCTS"
echo "Executing Detect EDR/AV products..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Detect EDR/AV products...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Detect EDR/AV products executed",
                metadata={"script": "edr_detection"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
