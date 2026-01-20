"""Slack/Teams history script."""

from ..base import OperatorScript, ScriptResult


class ChatHistory(OperatorScript):
    """Slack/Teams history."""
    
    name = "Slack/Teams History"
    description = "Slack/Teams history"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SLACK/TEAMS HISTORY"
echo "Executing Slack/Teams history..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Slack/Teams history...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Slack/Teams history executed",
                metadata={"script": "chat_history"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
