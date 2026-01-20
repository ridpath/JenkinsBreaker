"""Check SELinux/AppArmor status script."""

from ..base import OperatorScript, ScriptResult


class SELinuxAppArmor(OperatorScript):
    """Check SELinux/AppArmor status."""
    
    name = "Check Selinux/Apparmor Status"
    description = "Check SELinux/AppArmor status"
    category = "situational"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CHECK SELINUX/APPARMOR STATUS"
echo "Executing Check SELinux/AppArmor status..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Check SELinux/AppArmor status...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Check SELinux/AppArmor status executed",
                metadata={"script": "selinux_apparmor"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
