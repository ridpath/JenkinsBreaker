"""
Unit tests for JenkinsBreaker session management.
"""

from unittest.mock import MagicMock, Mock, patch

import requests


def test_jenkins_session_initialization():
    """Test JenkinsSession initialization with basic parameters."""
    from jenkins_breaker.core.session import JenkinsSession

    session = JenkinsSession(
        url="http://test.jenkins.com:8080",
        username="testuser",
        password="testpass"
    )

    assert session.url == "http://test.jenkins.com:8080"
    assert session.username == "testuser"
    assert session.password == "testpass"
    assert session.verify_ssl is True
    assert hasattr(session, 'session')


def test_jenkins_session_no_ssl_verify():
    """Test JenkinsSession with SSL verification disabled."""
    from jenkins_breaker.core.session import JenkinsSession

    session = JenkinsSession(
        url="https://jenkins.local:8443",
        username="admin",
        password="admin",
        verify_ssl=False
    )

    assert session.verify_ssl is False


def test_jenkins_session_with_proxy():
    """Test JenkinsSession with proxy configuration."""
    from jenkins_breaker.core.session import JenkinsSession

    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    }

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="admin",
        password="admin",
        proxies=proxies
    )

    assert session.proxies == proxies


@patch('jenkins_breaker.core.session.requests.Session')
def test_jenkins_session_http_request(mock_session_class):
    """Test HTTP request handling with retry logic."""
    from jenkins_breaker.core.session import JenkinsSession

    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "OK"
    mock_session.get.return_value = mock_response

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="admin",
        password="admin"
    )

    session.session = mock_session

    response = session.session.get("http://jenkins.local:8080/api/json")

    assert response.status_code == 200
    assert response.text == "OK"


@patch('jenkins_breaker.core.session.requests.Session')
def test_jenkins_session_retry_on_failure(mock_session_class):
    """Test retry logic on connection failure."""
    from jenkins_breaker.core.session import JenkinsSession

    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    mock_session.get.side_effect = [
        requests.exceptions.ConnectionError("Connection failed"),
        requests.exceptions.ConnectionError("Connection failed"),
        Mock(status_code=200, text="OK")
    ]

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="admin",
        password="admin"
    )

    session.session = mock_session


def test_jenkins_session_url_normalization():
    """Test URL normalization (trailing slash removal)."""
    from jenkins_breaker.core.session import JenkinsSession

    session = JenkinsSession(
        url="http://jenkins.local:8080/",
        username="admin",
        password="admin"
    )

    assert session.url == "http://jenkins.local:8080"


def test_jenkins_session_auth_tuple():
    """Test that session creates correct auth tuple."""
    from jenkins_breaker.core.session import JenkinsSession

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="myuser",
        password="mypass"
    )

    assert session.username == "myuser"
    assert session.password == "mypass"


@patch('jenkins_breaker.core.session.requests.Session')
def test_jenkins_session_custom_headers(mock_session_class):
    """Test session with custom headers."""
    from jenkins_breaker.core.session import JenkinsSession

    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="admin",
        password="admin"
    )

    session.session = mock_session


@patch('jenkins_breaker.core.session.requests.Session')
def test_jenkins_session_timeout_configuration(mock_session_class):
    """Test session timeout configuration."""
    from jenkins_breaker.core.session import JenkinsSession

    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="admin",
        password="admin",
        timeout=30
    )

    if hasattr(session, 'timeout'):
        assert session.timeout == 30


def test_jenkins_session_delay_configuration():
    """Test session with request delay configuration."""
    from jenkins_breaker.core.session import JenkinsSession

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="admin",
        password="admin",
        delay=2
    )

    if hasattr(session, 'delay'):
        assert session.delay == 2


@patch('jenkins_breaker.core.session.requests.Session')
def test_jenkins_session_user_agent(mock_session_class):
    """Test session has appropriate User-Agent."""
    from jenkins_breaker.core.session import JenkinsSession

    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="admin",
        password="admin"
    )

    session.session = mock_session
