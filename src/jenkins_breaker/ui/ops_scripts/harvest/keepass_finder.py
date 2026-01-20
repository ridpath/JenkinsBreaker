"""Find KeePass/1Password databases script."""

from ..base import OperatorScript, ScriptResult


class KeePassFinder(OperatorScript):
    """Find KeePass/1Password databases."""
    
    name = "Find Keepass/1Password Databases"
    description = "Find KeePass/1Password databases"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] FIND KEEPASS/1PASSWORD DATABASES"
echo "Executing Find KeePass/1Password databases..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Find KeePass/1Password databases...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Find KeePass/1Password databases executed",
                metadata={"script": "keepass_finder"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
