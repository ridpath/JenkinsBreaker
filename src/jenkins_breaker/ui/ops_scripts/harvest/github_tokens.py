"""GitHub personal access tokens script."""

from ..base import OperatorScript, ScriptResult


class GitHubTokens(OperatorScript):
    """GitHub personal access tokens."""
    
    name = "Github Personal Access Tokens"
    description = "GitHub personal access tokens"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] GITHUB PERSONAL ACCESS TOKENS"
echo "Executing GitHub personal access tokens..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running GitHub personal access tokens...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="GitHub personal access tokens executed",
                metadata={"script": "github_tokens"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
