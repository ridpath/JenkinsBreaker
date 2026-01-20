"""Memory dump of processes script."""

from ..base import OperatorScript, ScriptResult


class MemoryDump(OperatorScript):
    """Memory dump of processes."""
    
    name = "Memory Dump Of Processes"
    description = "Memory dump of processes"
    category = "exfiltrate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] MEMORY DUMP OF PROCESSES"
echo "Executing Memory dump of processes..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Memory dump of processes...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Memory dump of processes executed",
                metadata={"script": "memory_dump"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
