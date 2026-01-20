"""
CSRF crumb management and authentication validation for Jenkins.
"""

import time
from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class CrumbData:
    """CSRF crumb data."""

    field_name: str
    value: str

    def to_header(self) -> dict[str, str]:
        """Convert to header dictionary."""
        return {self.field_name: self.value}


class CrumbManager:
    """
    Manages Jenkins CSRF crumb tokens.

    Jenkins uses CSRF protection via crumb tokens that must be included
    in POST requests. This class handles fetching and injecting crumbs.

    Example:
        manager = CrumbManager(
            base_url="http://localhost:8080",
            auth=("admin", "admin")
        )
        manager.fetch()
        headers = manager.inject({})
    """

    def __init__(
        self,
        base_url: str,
        auth: Optional[tuple[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        proxies: Optional[dict[str, str]] = None,
        delay: float = 0.0,
        verify_ssl: bool = False,
        timeout: int = 5
    ) -> None:
        """
        Initialize crumb manager.

        Args:
            base_url: Jenkins base URL
            auth: (username, password) tuple
            headers: Custom headers
            proxies: Proxy configuration
            delay: Delay before requests (seconds)
            verify_ssl: Enable SSL verification
            timeout: Request timeout (seconds)
        """
        self.base_url = base_url.rstrip('/')
        self.auth = auth
        self.headers = headers or {}
        self.proxies = proxies or {}
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._crumb: Optional[CrumbData] = None
        self._fetch_count = 0

    @property
    def crumb(self) -> Optional[CrumbData]:
        """Get current crumb data."""
        return self._crumb

    @property
    def is_fetched(self) -> bool:
        """Check if crumb has been fetched."""
        return self._crumb is not None

    def fetch(self, force: bool = False) -> bool:
        """
        Fetch CSRF crumb from Jenkins.

        Args:
            force: Force refetch even if crumb exists

        Returns:
            bool: True if successful, False otherwise
        """
        if self._crumb and not force:
            return True

        if self.delay > 0:
            time.sleep(self.delay)

        try:
            url = f"{self.base_url}/crumbIssuer/api/json"

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

            field_name = data.get('crumbRequestField')
            value = data.get('crumb')

            if not field_name or not value:
                return False

            self._crumb = CrumbData(field_name=field_name, value=value)
            self._fetch_count += 1

            return True

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                self.csrf_disabled = True
                return False
            raise

        except (requests.exceptions.RequestException, ValueError, KeyError):
            return False

    def inject(self, headers: dict[str, str]) -> dict[str, str]:
        """
        Inject crumb into headers dictionary.

        Automatically fetches crumb if not already fetched.

        Args:
            headers: Headers dictionary to modify

        Returns:
            Updated headers dictionary
        """
        if not self._crumb:
            self.fetch()

        if self._crumb:
            headers[self._crumb.field_name] = self._crumb.value

        return headers

    def get_header(self) -> dict[str, str]:
        """
        Get crumb as header dictionary.

        Returns:
            Header dictionary with crumb, empty if not fetched
        """
        if not self._crumb:
            self.fetch()

        if self._crumb:
            return self._crumb.to_header()

        return {}

    def clear(self) -> None:
        """Clear stored crumb data."""
        self._crumb = None

    def validate_crumb(self) -> bool:
        """
        Validate that the crumb works by testing with a safe POST request.

        Returns:
            bool: True if crumb is valid and accepted
        """
        if not self._crumb:
            if not self.fetch():
                return False

        try:
            url = f"{self.base_url}/user/admin/descriptorByName/hudson.security.HudsonPrivateSecurityRealm/checkName"
            headers = self.headers.copy()
            headers = self.inject(headers)

            response = requests.post(
                url,
                auth=self.auth,
                headers=headers,
                data={'value': 'testuser'},
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            return response.status_code in [200, 404, 405]

        except requests.exceptions.RequestException:
            return False

    def check_crumb_binding(self) -> dict:
        """
        Check if crumb is bound to IP address or session ID.

        Returns:
            dict: Vulnerability test results
        """
        if not self._crumb:
            if not self.fetch():
                return {'tested': False, 'reason': 'No crumb available'}

        results = {
            'tested': True,
            'no_ip_binding': False,
            'no_session_binding': False,
            'replay_vulnerable': False
        }

        try:
            url = f"{self.base_url}/user/admin/descriptorByName/hudson.security.HudsonPrivateSecurityRealm/checkName"

            headers_without_cookies = self.headers.copy()
            headers_without_cookies = self.inject(headers_without_cookies)
            if 'Cookie' in headers_without_cookies:
                del headers_without_cookies['Cookie']

            response = requests.post(
                url,
                headers=headers_without_cookies,
                data={'value': 'testuser'},
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=self.timeout,
                allow_redirects=False
            )

            if response.status_code in [200, 404, 405]:
                results['no_session_binding'] = True
                results['replay_vulnerable'] = True

        except requests.exceptions.RequestException:
            pass

        return results

    def test_rotation(self, num_requests: int = 10) -> dict:
        """
        Test if crumb rotates by making rapid requests.

        Args:
            num_requests: Number of requests to make

        Returns:
            dict: Rotation test results
        """
        if not self._crumb:
            if not self.fetch():
                return {'tested': False, 'reason': 'No crumb available'}

        original_crumb = self._crumb.value
        crumbs_seen = {original_crumb}

        for _ in range(num_requests):
            self.clear()
            if self.fetch():
                crumbs_seen.add(self._crumb.value)

        return {
            'tested': True,
            'rotates': len(crumbs_seen) > 1,
            'unique_crumbs': len(crumbs_seen),
            'total_requests': num_requests
        }

    def __repr__(self) -> str:
        """String representation."""
        if self._crumb:
            return f"<CrumbManager {self._crumb.field_name}={self._crumb.value[:16]}... (fetched {self._fetch_count} times)>"
        return "<CrumbManager (no crumb)>"


class AuthenticationValidator:
    """
    Validates Jenkins authentication and permissions.
    """

    def __init__(
        self,
        base_url: str,
        auth: Optional[tuple[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        proxies: Optional[dict[str, str]] = None,
        verify_ssl: bool = False,
        timeout: int = 5
    ) -> None:
        """
        Initialize authentication validator.

        Args:
            base_url: Jenkins base URL
            auth: (username, password) tuple
            headers: Custom headers
            proxies: Proxy configuration
            verify_ssl: Enable SSL verification
            timeout: Request timeout (seconds)
        """
        self.base_url = base_url.rstrip('/')
        self.auth = auth
        self.headers = headers or {}
        self.proxies = proxies or {}
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def check_authenticated(self) -> bool:
        """
        Check if credentials are valid.

        Returns:
            bool: True if authenticated, False otherwise
        """
        try:
            url = f"{self.base_url}/me/api/json"

            response = requests.get(
                url,
                auth=self.auth,
                headers=self.headers,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            return response.status_code == 200

        except requests.exceptions.RequestException:
            return False

    def check_admin(self) -> bool:
        """
        Check if user has admin privileges.

        Returns:
            bool: True if admin, False otherwise
        """
        try:
            url = f"{self.base_url}/manage"

            response = requests.get(
                url,
                auth=self.auth,
                headers=self.headers,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            return response.status_code == 200

        except requests.exceptions.RequestException:
            return False

    def get_permissions(self) -> dict[str, bool]:
        """
        Enumerate user permissions.

        Returns:
            Dictionary of permission checks
        """
        permissions = {
            'authenticated': self.check_authenticated(),
            'admin': False,
            'script_console': False,
            'credentials_read': False,
            'job_configure': False
        }

        if not permissions['authenticated']:
            return permissions

        try:
            endpoints = {
                'admin': '/manage',
                'script_console': '/script',
                'credentials_read': '/credentials/store/system/domain/_/api/json',
                'job_configure': '/createItem'
            }

            for perm, endpoint in endpoints.items():
                url = f"{self.base_url}{endpoint}"

                response = requests.get(
                    url,
                    auth=self.auth,
                    headers=self.headers,
                    proxies=self.proxies,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )

                permissions[perm] = response.status_code != 403

        except requests.exceptions.RequestException:
            pass

        return permissions
