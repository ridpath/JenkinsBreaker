"""Redis credential dump script."""

from ..base import OperatorScript, ScriptResult


class RedisDump(OperatorScript):
    """Redis credential dump."""
    
    name = "Redis Credential Dump"
    description = "Redis credential dump"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] REDIS CREDENTIAL DUMP"
echo "Executing Redis credential dump..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Redis credential dump...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Redis credential dump executed",
                metadata={"script": "redis_dump"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
