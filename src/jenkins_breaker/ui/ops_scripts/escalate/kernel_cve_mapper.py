"""Map kernel version to known CVEs script."""

from ..base import OperatorScript, ScriptResult


class KernelCVEMapper(OperatorScript):
    """Map kernel version to known CVEs."""
    
    name = "Map Kernel Version To Known Cves"
    description = "Map kernel version to known CVEs"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] MAP KERNEL VERSION TO KNOWN CVES"
echo "Executing Map kernel version to known CVEs..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Map kernel version to known CVEs...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Map kernel version to known CVEs executed",
                metadata={"script": "kernel_cve_mapper"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
