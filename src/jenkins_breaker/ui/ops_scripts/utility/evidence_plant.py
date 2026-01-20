"""Evidence planting script."""

from ..base import OperatorScript, ScriptResult


class EvidencePlant(OperatorScript):
    """Evidence planting."""
    
    name = "Evidence Planting"
    description = "Evidence planting"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] EVIDENCE PLANTING"
echo "Executing Evidence planting..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Evidence planting...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Evidence planting executed",
                metadata={"script": "evidence_plant"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
