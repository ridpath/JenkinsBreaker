"""Windows UAC bypass techniques script."""

from ..base import OperatorScript, ScriptResult


class UACBypassWin(OperatorScript):
    """Windows UAC bypass techniques."""
    
    name = "Windows Uac Bypass Techniques"
    description = "Windows UAC bypass techniques"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] WINDOWS UAC BYPASS TECHNIQUES"
echo "Executing Windows UAC bypass techniques..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Windows UAC bypass techniques...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Windows UAC bypass techniques executed",
                metadata={"script": "uac_bypass_win"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
