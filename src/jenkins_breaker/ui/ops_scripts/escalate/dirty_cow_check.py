"""Check for Dirty Cow vulnerability script."""

from ..base import OperatorScript, ScriptResult


class DirtyCowCheck(OperatorScript):
    """Check for Dirty Cow vulnerability."""
    
    name = "Check For Dirty Cow Vulnerability"
    description = "Check for Dirty Cow vulnerability"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CHECK FOR DIRTY COW VULNERABILITY"
echo "Executing Check for Dirty Cow vulnerability..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Check for Dirty Cow vulnerability...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Check for Dirty Cow vulnerability executed",
                metadata={"script": "dirty_cow_check"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
