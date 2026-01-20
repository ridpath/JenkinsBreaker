"""PyPI tokens script."""

from ..base import OperatorScript, ScriptResult


class PyPITokens(OperatorScript):
    """PyPI tokens."""
    
    name = "Pypi Tokens"
    description = "PyPI tokens"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PYPI TOKENS"
echo "Executing PyPI tokens..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running PyPI tokens...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="PyPI tokens executed",
                metadata={"script": "pypi_tokens"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
