"""Packet capture setup script."""

from ..base import OperatorScript, ScriptResult


class PacketCapture(OperatorScript):
    """Packet capture setup."""
    
    name = "Packet Capture Setup"
    description = "Packet capture setup"
    category = "utility"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PACKET CAPTURE SETUP"
echo "Executing Packet capture setup..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running Packet capture setup...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Packet capture setup executed",
                metadata={"script": "packet_capture"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
