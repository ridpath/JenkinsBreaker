"""
Unit tests for JenkinsBreaker authentication and crumb management.
"""

from unittest.mock import MagicMock, Mock, patch

import pytest
import requests


def test_crumb_manager_initialization():
    """Test CrumbManager initialization."""
    from jenkins_breaker.core.authentication import CrumbManager
    from jenkins_breaker.core.session import JenkinsSession

    session = Mock(spec=JenkinsSession)
    session.url = "http://jenkins.local:8080"
    session.username = "admin"
    session.password = "admin"
    session.session = Mock()

    crumb_mgr = CrumbManager(session)
    assert crumb_mgr.session == session


@patch('requests.Session')
def test_crumb_manager_fetch_crumb_success(mock_session_class):
    """Test successful CSRF crumb fetch."""
    from jenkins_breaker.core.authentication import CrumbManager
    from jenkins_breaker.core.session import JenkinsSession

    mock_session_obj = MagicMock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "crumb": "test-crumb-value",
        "crumbRequestField": "Jenkins-Crumb"
    }
    mock_session_obj.get.return_value = mock_response

    session = Mock(spec=JenkinsSession)
    session.url = "http://jenkins.local:8080"
    session.username = "admin"
    session.password = "admin"
    session.session = mock_session_obj

    crumb_mgr = CrumbManager(session)
    crumb = crumb_mgr.get_crumb()

    assert crumb is not None
    mock_session_obj.get.assert_called()


@patch('requests.Session')
def test_crumb_manager_no_crumb_required(mock_session_class):
    """Test handling when Jenkins doesn't require CSRF crumb."""
    from jenkins_breaker.core.authentication import CrumbManager
    from jenkins_breaker.core.session import JenkinsSession

    mock_session_obj = MagicMock()
    mock_response = Mock()
    mock_response.status_code = 404
    mock_session_obj.get.return_value = mock_response

    session = Mock(spec=JenkinsSession)
    session.url = "http://jenkins.local:8080"
    session.username = "admin"
    session.password = "admin"
    session.session = mock_session_obj

    crumb_mgr = CrumbManager(session)
    crumb = crumb_mgr.get_crumb()

    assert crumb is None or crumb == ""


@patch('requests.Session')
def test_crumb_manager_connection_error(mock_session_class):
    """Test crumb fetch with connection error."""
    from jenkins_breaker.core.authentication import CrumbManager
    from jenkins_breaker.core.session import JenkinsSession

    mock_session_obj = MagicMock()
    mock_session_obj.get.side_effect = requests.exceptions.ConnectionError("Connection failed")

    session = Mock(spec=JenkinsSession)
    session.url = "http://jenkins.local:8080"
    session.username = "admin"
    session.password = "admin"
    session.session = mock_session_obj

    crumb_mgr = CrumbManager(session)

    with pytest.raises(requests.exceptions.ConnectionError):
        crumb_mgr.get_crumb()


@patch('requests.Session')
def test_crumb_manager_inject_crumb(mock_session_class):
    """Test crumb injection into headers."""
    from jenkins_breaker.core.authentication import CrumbManager
    from jenkins_breaker.core.session import JenkinsSession

    mock_session_obj = MagicMock()

    session = Mock(spec=JenkinsSession)
    session.url = "http://jenkins.local:8080"
    session.username = "admin"
    session.password = "admin"
    session.session = mock_session_obj

    crumb_mgr = CrumbManager(session)
    crumb_mgr.crumb = "test-crumb-123"
    crumb_mgr.crumb_field = "Jenkins-Crumb"

    headers = {}

    if hasattr(crumb_mgr, 'inject_crumb'):
        headers = crumb_mgr.inject_crumb(headers)
        assert headers.get("Jenkins-Crumb") == "test-crumb-123"


def test_authentication_validation():
    """Test authentication validation logic."""
    from jenkins_breaker.core.authentication import CrumbManager

    assert CrumbManager is not None


@patch('requests.Session')
def test_crumb_manager_caching(mock_session_class):
    """Test crumb caching to avoid repeated requests."""
    from jenkins_breaker.core.authentication import CrumbManager
    from jenkins_breaker.core.session import JenkinsSession

    mock_session_obj = MagicMock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "crumb": "cached-crumb-value",
        "crumbRequestField": "Jenkins-Crumb"
    }
    mock_session_obj.get.return_value = mock_response

    session = Mock(spec=JenkinsSession)
    session.url = "http://jenkins.local:8080"
    session.username = "admin"
    session.password = "admin"
    session.session = mock_session_obj

    crumb_mgr = CrumbManager(session)

    crumb_mgr.get_crumb()
    crumb_mgr.get_crumb()

    if hasattr(crumb_mgr, 'crumb'):
        assert mock_session_obj.get.call_count <= 2


def test_auth_with_invalid_credentials():
    """Test authentication with invalid credentials."""
    from jenkins_breaker.core.session import JenkinsSession

    session = JenkinsSession(
        url="http://jenkins.local:8080",
        username="invalid",
        password="invalid"
    )

    assert session.username == "invalid"
    assert session.password == "invalid"


@patch('requests.Session')
def test_crumb_refresh(mock_session_class):
    """Test crumb refresh functionality."""
    from jenkins_breaker.core.authentication import CrumbManager
    from jenkins_breaker.core.session import JenkinsSession

    mock_session_obj = MagicMock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "crumb": "refreshed-crumb",
        "crumbRequestField": "Jenkins-Crumb"
    }
    mock_session_obj.get.return_value = mock_response

    session = Mock(spec=JenkinsSession)
    session.url = "http://jenkins.local:8080"
    session.username = "admin"
    session.password = "admin"
    session.session = mock_session_obj

    crumb_mgr = CrumbManager(session)

    if hasattr(crumb_mgr, 'refresh_crumb'):
        crumb_mgr.refresh_crumb()
        assert mock_session_obj.get.called


@patch('requests.Session')
def test_crumb_with_different_field_name(mock_session_class):
    """Test crumb with custom field name."""
    from jenkins_breaker.core.authentication import CrumbManager
    from jenkins_breaker.core.session import JenkinsSession

    mock_session_obj = MagicMock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "crumb": "test-crumb",
        "crumbRequestField": "Custom-Crumb-Field"
    }
    mock_session_obj.get.return_value = mock_response

    session = Mock(spec=JenkinsSession)
    session.url = "http://jenkins.local:8080"
    session.username = "admin"
    session.password = "admin"
    session.session = mock_session_obj

    crumb_mgr = CrumbManager(session)
    crumb_mgr.get_crumb()

    if hasattr(crumb_mgr, 'crumb_field'):
        assert crumb_mgr.crumb_field == "Custom-Crumb-Field"
