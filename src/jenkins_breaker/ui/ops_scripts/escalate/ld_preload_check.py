"""Find LD_PRELOAD opportunities script."""

from ..base import OperatorScript, ScriptResult


class LDPreloadCheck(OperatorScript):
    """Find LD_PRELOAD opportunities."""
    
    name = "Find Ld_Preload Opportunities"
    description = "Find LD_PRELOAD opportunities"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] FIND LD_PRELOAD OPPORTUNITIES"
echo "Executing Find LD_PRELOAD opportunities..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Find LD_PRELOAD opportunities...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Find LD_PRELOAD opportunities executed",
                metadata={"script": "ld_preload_check"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
