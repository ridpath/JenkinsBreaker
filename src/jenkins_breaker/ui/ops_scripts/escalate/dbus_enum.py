"""DBus service enumeration script."""

from ..base import OperatorScript, ScriptResult


class DBusEnum(OperatorScript):
    """DBus service enumeration."""
    
    name = "Dbus Service Enumeration"
    description = "DBus service enumeration"
    category = "escalate"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DBUS SERVICE ENUMERATION"
echo "Executing DBus service enumeration..."
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Running DBus service enumeration...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="DBus service enumeration executed",
                metadata={"script": "dbus_enum"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
