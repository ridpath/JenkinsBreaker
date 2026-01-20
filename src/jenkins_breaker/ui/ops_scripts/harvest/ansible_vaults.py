"""Ansible vault passwords script."""

from ..base import OperatorScript, ScriptResult


class AnsibleVaults(OperatorScript):
    """Ansible vault passwords."""
    
    name = "Ansible Vault Passwords"
    description = "Ansible vault passwords"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] ANSIBLE VAULT PASSWORDS"
echo "Executing Ansible vault passwords..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Ansible vault passwords...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Ansible vault passwords executed",
                metadata={"script": "ansible_vaults"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
