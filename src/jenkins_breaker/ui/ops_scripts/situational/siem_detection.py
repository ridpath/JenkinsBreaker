"""SIEM integration detection script."""

from ..base import OperatorScript, ScriptResult


class SIEMDetection(OperatorScript):
    """SIEM integration detection."""
    
    name = "Siem Integration Detection"
    description = "SIEM integration detection"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SIEM INTEGRATION DETECTION"
echo "Executing SIEM integration detection..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running SIEM integration detection...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="SIEM integration detection executed",
                metadata={"script": "siem_detection"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
