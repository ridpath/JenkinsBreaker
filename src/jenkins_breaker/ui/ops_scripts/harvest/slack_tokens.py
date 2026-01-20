"""Slack API tokens script."""

from ..base import OperatorScript, ScriptResult


class SlackTokens(OperatorScript):
    """Slack API tokens."""
    
    name = "Slack Api Tokens"
    description = "Slack API tokens"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SLACK API TOKENS"
echo "Executing Slack API tokens..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Slack API tokens...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Slack API tokens executed",
                metadata={"script": "slack_tokens"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
