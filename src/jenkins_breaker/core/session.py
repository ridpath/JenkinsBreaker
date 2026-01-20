"""
Jenkins session management with HTTP request handling, retries, and authentication.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin

import requests

from jenkins_breaker.core.authentication import CrumbManager


@dataclass
class SessionConfig:
    """Configuration for Jenkins session."""

    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    delay: float = 0.0
    verify_ssl: bool = False
    timeout: int = 10
    max_retries: int = 3
    retry_delay: float = 1.0

    def __post_init__(self) -> None:
        """Validate and normalize configuration."""
        self.url = self.url.rstrip('/')
        if not self.url.startswith(('http://', 'https://')):
            raise ValueError(f"Invalid URL: {self.url}")


class JenkinsSession:
    """
    Manages HTTP session with Jenkins instance.

    Handles:
    - Connection initialization and verification
    - Request execution with retry logic
    - Proxy and header configuration
    - Rate limiting via delay
    - Authentication state

    Example:
        config = SessionConfig(
            url="http://localhost:8080",
            username="admin",
            password="admin"
        )
        session = JenkinsSession(config)
        session.connect()
        response = session.get("/api/json")
    """

    def __init__(self, config: SessionConfig) -> None:
        """
        Initialize Jenkins session.

        Args:
            config: SessionConfig with connection parameters
        """
        self.config = config
        self.base_url = config.url
        self._session: Optional[requests.Session] = None
        self._authenticated = False
        self._version: Optional[str] = None
        self.crumb_manager: Optional[CrumbManager] = None

        requests.packages.urllib3.disable_warnings()

    @property
    def session(self) -> requests.Session:
        """Get or create requests session."""
        if self._session is None:
            self._session = requests.Session()

            if self.config.username and self.config.password:
                self._session.auth = (self.config.username, self.config.password)

            self._session.headers.update(self.config.headers)

            if self.config.proxy:
                self._session.proxies = {
                    'http': self.config.proxy,
                    'https': self.config.proxy
                }

            self._session.verify = self.config.verify_ssl

        return self._session

    @property
    def auth(self) -> Optional[tuple[str, str]]:
        """Get authentication tuple."""
        if self.config.username and self.config.password:
            return (self.config.username, self.config.password)
        return None

    @property
    def version(self) -> Optional[str]:
        """Get cached Jenkins version."""
        return self._version

    @property
    def is_authenticated(self) -> bool:
        """Check if session is authenticated."""
        return self._authenticated

    def connect(self) -> bool:
        """
        Initialize connection to Jenkins and verify accessibility.

        Returns:
            bool: True if connection successful, False otherwise

        Raises:
            ConnectionError: If unable to connect after retries
        """
        try:
            response = self.get('/')

            if response.status_code == 200:
                self._authenticated = True

                if 'X-Jenkins' in response.headers:
                    self._version = response.headers['X-Jenkins']

                self.crumb_manager = CrumbManager(
                    base_url=self.base_url,
                    auth=self.auth,
                    headers=self.config.headers,
                    proxies=self.session.proxies if hasattr(self.session, 'proxies') else {},
                    verify_ssl=self.config.verify_ssl,
                    timeout=self.config.timeout
                )
                self.crumb_manager.fetch()

                return True
            elif response.status_code == 403:
                self._authenticated = False

                self.crumb_manager = CrumbManager(
                    base_url=self.base_url,
                    auth=self.auth,
                    headers=self.config.headers,
                    proxies=self.session.proxies if hasattr(self.session, 'proxies') else {},
                    verify_ssl=self.config.verify_ssl,
                    timeout=self.config.timeout
                )
                self.crumb_manager.fetch()

                return True
            else:
                return False

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to connect to {self.base_url}: {e}")

    def _apply_delay(self) -> None:
        """Apply configured delay between requests."""
        if self.config.delay > 0:
            time.sleep(self.config.delay)

    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any
    ) -> requests.Response:
        """
        Execute HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (relative to base URL)
            **kwargs: Additional request parameters

        Returns:
            Response object

        Raises:
            requests.exceptions.RequestException: On failure after retries
        """
        self._apply_delay()

        url = urljoin(self.base_url, endpoint)

        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('verify', self.config.verify_ssl)

        last_exception = None

        for attempt in range(self.config.max_retries):
            try:
                response = self.session.request(method, url, **kwargs)
                return response

            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                    continue

            except requests.exceptions.ConnectionError as e:
                last_exception = e
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                    continue

        raise requests.exceptions.RequestException(
            f"Request failed after {self.config.max_retries} attempts: {last_exception}"
        )

    def get(self, endpoint: str, **kwargs: Any) -> requests.Response:
        """
        Execute GET request.

        Args:
            endpoint: API endpoint
            **kwargs: Additional request parameters

        Returns:
            Response object
        """
        return self._make_request('GET', endpoint, **kwargs)

    def post(
        self,
        endpoint: str,
        data: Optional[dict[str, Any]] = None,
        json: Optional[dict[str, Any]] = None,
        **kwargs: Any
    ) -> requests.Response:
        """
        Execute POST request.

        Args:
            endpoint: API endpoint
            data: Form data
            json: JSON payload
            **kwargs: Additional request parameters

        Returns:
            Response object
        """
        return self._make_request('POST', endpoint, data=data, json=json, **kwargs)

    def put(
        self,
        endpoint: str,
        data: Optional[dict[str, Any]] = None,
        json: Optional[dict[str, Any]] = None,
        **kwargs: Any
    ) -> requests.Response:
        """
        Execute PUT request.

        Args:
            endpoint: API endpoint
            data: Form data
            json: JSON payload
            **kwargs: Additional request parameters

        Returns:
            Response object
        """
        return self._make_request('PUT', endpoint, data=data, json=json, **kwargs)

    def delete(self, endpoint: str, **kwargs: Any) -> requests.Response:
        """
        Execute DELETE request.

        Args:
            endpoint: API endpoint
            **kwargs: Additional request parameters

        Returns:
            Response object
        """
        return self._make_request('DELETE', endpoint, **kwargs)

    def head(self, endpoint: str, **kwargs: Any) -> requests.Response:
        """
        Execute HEAD request.

        Args:
            endpoint: API endpoint
            **kwargs: Additional request parameters

        Returns:
            Response object
        """
        return self._make_request('HEAD', endpoint, **kwargs)

    def get_json(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        """
        Execute GET request and parse JSON response.

        Args:
            endpoint: API endpoint
            **kwargs: Additional request parameters

        Returns:
            Parsed JSON data

        Raises:
            ValueError: If response is not valid JSON
        """
        response = self.get(endpoint, **kwargs)
        response.raise_for_status()
        return response.json()

    def post_json(
        self,
        endpoint: str,
        data: Optional[dict[str, Any]] = None,
        **kwargs: Any
    ) -> dict[str, Any]:
        """
        Execute POST request and parse JSON response.

        Args:
            endpoint: API endpoint
            data: JSON payload
            **kwargs: Additional request parameters

        Returns:
            Parsed JSON data

        Raises:
            ValueError: If response is not valid JSON
        """
        response = self.post(endpoint, json=data, **kwargs)
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        """Close the session and cleanup resources."""
        if self._session:
            self._session.close()
            self._session = None
            self._authenticated = False

    def __enter__(self) -> "JenkinsSession":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()

    def __repr__(self) -> str:
        """String representation."""
        auth_status = "authenticated" if self._authenticated else "unauthenticated"
        version_str = f" v{self._version}" if self._version else ""
        return f"<JenkinsSession {self.base_url}{version_str} ({auth_status})>"
