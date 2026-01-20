"""NPM authentication tokens script."""

from ..base import OperatorScript, ScriptResult


class NPMTokens(OperatorScript):
    """NPM authentication tokens."""
    
    name = "Npm Authentication Tokens"
    description = "NPM authentication tokens"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] NPM AUTHENTICATION TOKENS"
echo "Executing NPM authentication tokens..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running NPM authentication tokens...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="NPM authentication tokens executed",
                metadata={"script": "npm_tokens"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
