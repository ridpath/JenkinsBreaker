"""MongoDB credential dump script."""

from ..base import OperatorScript, ScriptResult


class MongoDBDump(OperatorScript):
    """MongoDB credential dump."""
    
    name = "Mongodb Credential Dump"
    description = "MongoDB credential dump"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] MONGODB CREDENTIAL DUMP"
echo "Executing MongoDB credential dump..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running MongoDB credential dump...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="MongoDB credential dump executed",
                metadata={"script": "mongodb_dump"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
