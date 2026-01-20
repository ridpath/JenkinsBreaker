"""
Jenkins enumeration capabilities for version detection, plugin scanning, and job discovery.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional

import requests


@dataclass
class JenkinsVersion:
    """Jenkins version information."""

    version: str
    is_lts: bool = False
    source: str = "unknown"

    def as_tuple(self) -> tuple[int, ...]:
        """Convert version string to tuple of integers."""
        try:
            return tuple(int(x) for x in self.version.split('.'))
        except (ValueError, AttributeError):
            return (0, 0, 0)

    def is_vulnerable_to(self, max_version: str) -> bool:
        """
        Check if version is vulnerable (less than or equal to max version).

        Args:
            max_version: Maximum vulnerable version

        Returns:
            bool: True if vulnerable
        """
        try:
            current = self.as_tuple()
            max_ver = tuple(int(x) for x in max_version.split('.'))
            return current[:len(max_ver)] <= max_ver
        except (ValueError, AttributeError):
            return False


@dataclass
class PluginInfo:
    """Jenkins plugin information."""

    short_name: str
    version: str
    long_name: Optional[str] = None
    enabled: bool = True
    active: bool = True
    has_update: bool = False


@dataclass
class JobInfo:
    """Jenkins job information."""

    name: str
    url: str
    type: Optional[str] = None
    buildable: bool = True


@dataclass
class EnumerationResult:
    """Results from enumeration."""

    version: Optional[JenkinsVersion] = None
    plugins: list[PluginInfo] = field(default_factory=list)
    jobs: list[JobInfo] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    credentials: dict[str, Any] = field(default_factory=dict)


class JenkinsEnumerator:
    """
    Enumerates Jenkins instance for version, plugins, jobs, and vulnerabilities.

    Example:
        enumerator = JenkinsEnumerator(
            base_url="http://localhost:8080",
            auth=("admin", "admin")
        )
        version = enumerator.detect_version()
        plugins = enumerator.enumerate_plugins()
        jobs = enumerator.enumerate_jobs()
    """

    def __init__(
        self,
        base_url: str,
        auth: Optional[tuple[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        proxies: Optional[dict[str, str]] = None,
        verify_ssl: bool = False,
        timeout: int = 5,
        delay: float = 0.0
    ) -> None:
        """
        Initialize enumerator.

        Args:
            base_url: Jenkins base URL
            auth: (username, password) tuple
            headers: Custom headers
            proxies: Proxy configuration
            verify_ssl: Enable SSL verification
            timeout: Request timeout (seconds)
            delay: Delay between requests (seconds)
        """
        self.base_url = base_url.rstrip('/')
        self.auth = auth
        self.headers = headers or {}
        self.proxies = proxies or {}
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.delay = delay

    def detect_version(self) -> Optional[JenkinsVersion]:
        """
        Detect Jenkins version from headers and API responses.

        Returns:
            JenkinsVersion object or None if detection fails
        """
        version = None
        source = "unknown"

        try:
            response = requests.get(
                self.base_url,
                auth=self.auth,
                headers=self.headers,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if 'X-Jenkins' in response.headers:
                version = response.headers['X-Jenkins']
                source = "X-Jenkins header"

        except requests.exceptions.RequestException:
            pass

        if not version:
            try:
                url = f"{self.base_url}/api/json"
                response = requests.get(
                    url,
                    auth=self.auth,
                    headers=self.headers,
                    proxies=self.proxies,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    if 'X-Jenkins' in response.headers:
                        version = response.headers['X-Jenkins']
                        source = "API X-Jenkins header"

            except requests.exceptions.RequestException:
                pass

        if not version:
            try:
                url = f"{self.base_url}/login"
                response = requests.get(
                    url,
                    headers=self.headers,
                    proxies=self.proxies,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )

                match = re.search(r'Jenkins\s+(?:ver\.\s*)?(\d+\.\d+(?:\.\d+)?)', response.text)
                if match:
                    version = match.group(1)
                    source = "login page"

            except requests.exceptions.RequestException:
                pass

        if version:
            is_lts = bool(re.search(r'\d+\.\d+\.\d+', version))
            return JenkinsVersion(version=version, is_lts=is_lts, source=source)

        return None

    def enumerate_plugins(self) -> list[PluginInfo]:
        """
        Enumerate installed Jenkins plugins.

        Returns:
            List of PluginInfo objects
        """
        plugins = []

        try:
            url = f"{self.base_url}/pluginManager/api/json?depth=1"

            response = requests.get(
                url,
                auth=self.auth,
                headers=self.headers,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            response.raise_for_status()
            data = response.json()

            for plugin in data.get('plugins', []):
                plugins.append(PluginInfo(
                    short_name=plugin.get('shortName', ''),
                    version=plugin.get('version', ''),
                    long_name=plugin.get('longName'),
                    enabled=plugin.get('enabled', True),
                    active=plugin.get('active', True),
                    has_update=plugin.get('hasUpdate', False)
                ))

        except (requests.exceptions.RequestException, ValueError, KeyError):
            pass

        return plugins

    def enumerate_jobs(self) -> list[JobInfo]:
        """
        Enumerate Jenkins jobs.

        Returns:
            List of JobInfo objects
        """
        jobs = []

        try:
            url = f"{self.base_url}/api/json?tree=jobs[name,url,buildable,_class]"

            response = requests.get(
                url,
                auth=self.auth,
                headers=self.headers,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            response.raise_for_status()
            data = response.json()

            for job in data.get('jobs', []):
                jobs.append(JobInfo(
                    name=job.get('name', ''),
                    url=job.get('url', ''),
                    type=job.get('_class'),
                    buildable=job.get('buildable', True)
                ))

        except (requests.exceptions.RequestException, ValueError, KeyError):
            pass

        return jobs

    def check_plugin_vulnerable(self, plugin: PluginInfo) -> Optional[dict[str, Any]]:
        """
        Check if plugin version is known to be vulnerable.

        Args:
            plugin: PluginInfo object

        Returns:
            Vulnerability information or None
        """
        vulnerable_plugins = {
            'script-security': {
                'max_version': '1.75',
                'cve': 'CVE-2019-1003029',
                'description': 'Groovy sandbox bypass'
            },
            'git': {
                'max_version': '4.7.1',
                'cve': 'CVE-2021-21642',
                'description': 'Git plugin credential exposure'
            },
            'pipeline-groovy-lib': {
                'max_version': '2.21',
                'cve': 'CVE-2020-2190',
                'description': 'Arbitrary file read'
            }
        }

        if plugin.short_name in vulnerable_plugins:
            vuln = vulnerable_plugins[plugin.short_name]

            try:
                current_ver = tuple(int(x) for x in plugin.version.split('.'))
                max_ver = tuple(int(x) for x in vuln['max_version'].split('.'))

                if current_ver[:len(max_ver)] <= max_ver:
                    return {
                        'plugin': plugin.short_name,
                        'version': plugin.version,
                        'cve': vuln['cve'],
                        'description': vuln['description'],
                        'max_vulnerable_version': vuln['max_version']
                    }
            except (ValueError, AttributeError):
                pass

        return None

    def scan_vulnerabilities(self, version: JenkinsVersion) -> list[dict[str, Any]]:
        """
        Scan for known vulnerabilities based on version (potential vulnerabilities).

        Args:
            version: JenkinsVersion object

        Returns:
            List of vulnerability dictionaries marked as 'potential'
        """
        vulnerabilities = []

        vuln_map = {
            'CVE-2024-23897': {
                'max_version': '2.440',
                'max_lts_version': '2.426.3',
                'description': 'Arbitrary file read via CLI',
                'severity': 'critical'
            },
            'CVE-2019-1003029': {
                'max_version': '2.138',
                'description': 'Groovy sandbox bypass',
                'severity': 'critical'
            },
            'CVE-2019-1003030': {
                'max_version': '2.138',
                'description': 'Groovy sandbox bypass (SECURITY-1292)',
                'severity': 'critical'
            },
            'CVE-2018-1000861': {
                'max_version': '2.153',
                'max_lts_version': '2.138.3',
                'description': 'Arbitrary code execution via workspace file',
                'severity': 'critical'
            },
            'CVE-2017-1000353': {
                'max_version': '2.56',
                'max_lts_version': '2.46.1',
                'description': 'Unauthenticated RCE via Java deserialization',
                'severity': 'critical'
            }
        }

        for cve, info in vuln_map.items():
            if version.is_vulnerable_to(info['max_version']):
                vulnerabilities.append({
                    'cve': cve,
                    'description': info['description'],
                    'severity': info['severity'],
                    'max_version': info['max_version'],
                    'status': 'potential',
                    'method': 'version-based'
                })
            elif version.is_lts and 'max_lts_version' in info:
                if version.is_vulnerable_to(info['max_lts_version']):
                    vulnerabilities.append({
                        'cve': cve,
                        'description': info['description'],
                        'severity': info['severity'],
                        'max_version': info['max_lts_version'],
                        'status': 'potential',
                        'method': 'version-based'
                    })

        return vulnerabilities

    def test_vulnerabilities(self, session) -> list[dict[str, Any]]:
        """
        Test for actual vulnerabilities by running check_vulnerable() on all modules.

        Args:
            session: JenkinsSession instance

        Returns:
            List of confirmed vulnerability dictionaries
        """
        vulnerabilities = []

        try:
            from jenkins_breaker.modules.base import exploit_registry

            for cve_id in exploit_registry.list_cves():
                try:
                    exploit_module = exploit_registry.get(cve_id)

                    if exploit_module and hasattr(exploit_module, 'check_vulnerable'):
                        is_vulnerable = exploit_module.check_vulnerable(session)

                        if is_vulnerable:
                            metadata = exploit_registry.get_metadata(cve_id)

                            vulnerabilities.append({
                                'cve': cve_id,
                                'description': metadata.description if metadata else 'No description available',
                                'severity': metadata.severity if metadata else 'unknown',
                                'status': 'confirmed',
                                'method': 'check_vulnerable()',
                                'module': cve_id
                            })
                except Exception:
                    pass

        except ImportError:
            pass

        return vulnerabilities

    def enumerate_all(self, session=None, test_actual_vulns: bool = False,
                      auto_grab_credentials: bool = True, loot_manager=None) -> EnumerationResult:
        """
        Perform complete enumeration.

        Args:
            session: Optional JenkinsSession for actual vulnerability testing
            test_actual_vulns: If True and session provided, test actual vulnerabilities
            auto_grab_credentials: If True, automatically grab Jenkins credential files
            loot_manager: Optional LootManager instance to auto-add grabbed credentials

        Returns:
            EnumerationResult with all findings
        """
        result = EnumerationResult()

        result.version = self.detect_version()
        result.plugins = self.enumerate_plugins()
        result.jobs = self.enumerate_jobs()

        if result.version:
            result.vulnerabilities = self.scan_vulnerabilities(result.version)

        for plugin in result.plugins:
            vuln = self.check_plugin_vulnerable(plugin)
            if vuln:
                vuln['status'] = 'potential'
                vuln['method'] = 'plugin-version'
                result.vulnerabilities.append(vuln)

        if test_actual_vulns and session:
            confirmed_vulns = self.test_vulnerabilities(session)
            result.vulnerabilities.extend(confirmed_vulns)

        if auto_grab_credentials and session:
            try:
                from jenkins_breaker.postex.auto_loot import auto_grab_jenkins_credentials

                cred_result = auto_grab_jenkins_credentials(session, loot_manager)
                result.credentials = cred_result
            except Exception:
                pass

        return result
