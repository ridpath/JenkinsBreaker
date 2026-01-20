"""
Pytest configuration and fixtures for JenkinsBreaker testing.
"""

import os
import subprocess
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any, Optional

import pytest
import requests

# Test environment configuration
JENKINS_URL = os.getenv("JENKINS_URL", "http://localhost:8080")
JENKINS_USER = os.getenv("JENKINS_USER", "admin")
JENKINS_PASS = os.getenv("JENKINS_PASS", "admin")
DOCKER_CONTAINER = os.getenv("JENKINS_CONTAINER", "jenkins-lab")
WSL_DISTRO = os.getenv("WSL_DISTRO", "parrot")

# Test data paths
TEST_DIR = Path(__file__).parent
TEST_DATA_DIR = TEST_DIR / "data"
DOCKER_LAB_DIR = TEST_DIR / "docker" / "jenkins-lab"


@pytest.fixture(scope="session")
def jenkins_lab_container() -> str:
    """
    Ensure Jenkins lab Docker container is running.

    Returns:
        Container name if running

    Raises:
        RuntimeError: If container is not running
    """
    try:
        result = subprocess.run(
            ["wsl", "-d", WSL_DISTRO, "--", "docker", "ps", "-f", f"name={DOCKER_CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0 and DOCKER_CONTAINER in result.stdout:
            return DOCKER_CONTAINER
        else:
            raise RuntimeError(
                f"Jenkins lab container '{DOCKER_CONTAINER}' is not running. "
                f"Start it with: cd jenkins-lab && docker-compose up -d"
            )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Timeout checking Docker container status")
    except FileNotFoundError:
        raise RuntimeError("WSL not available. Docker tests require WSL.")


@pytest.fixture(scope="session")
def jenkins_ready(jenkins_lab_container: str) -> dict[str, str]:
    """
    Wait for Jenkins to be ready and return connection info.

    Args:
        jenkins_lab_container: Container name from jenkins_lab_container fixture

    Returns:
        Dictionary with url, username, password

    Raises:
        RuntimeError: If Jenkins doesn't become ready within timeout
    """
    max_retries = 30
    retry_interval = 2

    for attempt in range(max_retries):
        try:
            response = requests.get(
                f"{JENKINS_URL}/api/json",
                auth=(JENKINS_USER, JENKINS_PASS),
                timeout=5
            )

            if response.status_code == 200:
                return {
                    "url": JENKINS_URL,
                    "username": JENKINS_USER,
                    "password": JENKINS_PASS
                }
        except requests.exceptions.RequestException:
            pass

        if attempt < max_retries - 1:
            time.sleep(retry_interval)

    raise RuntimeError(
        f"Jenkins not ready at {JENKINS_URL} after {max_retries * retry_interval}s. "
        f"Check container logs: docker logs {jenkins_lab_container}"
    )


@pytest.fixture(scope="function")
def jenkins_session(jenkins_ready: dict[str, str]) -> Generator[Any, None, None]:
    """
    Create a JenkinsBreaker session for testing.

    Args:
        jenkins_ready: Connection info from jenkins_ready fixture

    Yields:
        Configured JenkinsSession instance
    """
    from jenkins_breaker.core.session import JenkinsSession, SessionConfig

    config = SessionConfig(
        url=jenkins_ready["url"],
        username=jenkins_ready["username"],
        password=jenkins_ready["password"],
        verify_ssl=False
    )

    session = JenkinsSession(config)

    try:
        yield session
    finally:
        if hasattr(session, 'close'):
            session.close()


@pytest.fixture(scope="function")
def jenkins_crumb(jenkins_session: Any) -> Optional[str]:
    """
    Get CSRF crumb for Jenkins session.

    Args:
        jenkins_session: JenkinsSession from jenkins_session fixture

    Returns:
        Crumb string or None if not required
    """
    from jenkins_breaker.core.authentication import CrumbManager

    crumb_mgr = CrumbManager(jenkins_session)
    return crumb_mgr.get_crumb()


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    """
    Create and return test data directory.

    Returns:
        Path to test_data directory
    """
    TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return TEST_DATA_DIR


@pytest.fixture(scope="session")
def jenkins_secrets(jenkins_lab_container: str, test_data_dir: Path) -> dict[str, Path]:
    """
    Extract Jenkins secret files from container for testing.

    Args:
        jenkins_lab_container: Container name
        test_data_dir: Test data directory path

    Returns:
        Dictionary mapping secret names to file paths
    """
    secrets = {}

    secret_paths = {
        "master_key": "/var/jenkins_home/secrets/master.key",
        "secret_key": "/var/jenkins_home/secret.key",
        "hudson_secret": "/var/jenkins_home/secrets/hudson.util.Secret",
        "credentials_xml": "/var/jenkins_home/credentials.xml",
        "mac_key": "/var/jenkins_home/secrets/org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.mac"
    }

    for name, container_path in secret_paths.items():
        local_path = test_data_dir / f"{name}"

        try:
            result = subprocess.run(
                ["wsl", "-d", WSL_DISTRO, "--", "docker", "exec", jenkins_lab_container, "cat", container_path],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                local_path.write_bytes(result.stdout)
                secrets[name] = local_path
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

    return secrets


@pytest.fixture(scope="function")
def planted_credentials() -> dict[str, dict[str, str]]:
    """
    Return dict of planted credentials in jenkins-lab for validation.

    Returns:
        Dictionary of credential types to expected values
    """
    return {
        "aws": {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "location": "/home/jenkins/.aws/credentials"
        },
        "ssh": {
            "private_key_path": "/home/jenkins/.ssh/id_rsa",
            "user": "deploy"
        },
        "npm": {
            "token": "npm_ExampleTokenString123456789",
            "location": "/home/jenkins/.npmrc"
        },
        "docker": {
            "username": "dockeruser",
            "password": "dockerpassword123",
            "location": "/home/jenkins/.docker/config.json"
        },
        "database": {
            "username": "dbadmin",
            "password": "DB_@dm1n_P@ssw0rd_2024!",
            "location": "/home/jenkins/.config/database.env"
        },
        "github": {
            "token": "ghp_ExampleTokenString123456789ABC",
            "credential_id": "github-token"
        },
        "api_master": {
            "key": "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
            "location": "/home/jenkins/.config/api_keys.env"
        }
    }


@pytest.fixture(scope="function")
def reset_jenkins_job(jenkins_session: Any) -> Generator[callable, None, None]:
    """
    Provide a function to reset Jenkins job configuration.

    Args:
        jenkins_session: JenkinsSession instance

    Yields:
        Function that resets specified job
    """
    job_backups = {}

    def backup_and_reset(job_name: str) -> None:
        """Backup job config and prepare for reset."""
        try:
            response = jenkins_session.session.get(
                f"{jenkins_session.url}/job/{job_name}/config.xml",
                auth=(jenkins_session.username, jenkins_session.password)
            )
            if response.status_code == 200:
                job_backups[job_name] = response.text
        except Exception:
            pass

    yield backup_and_reset

    for job_name, config in job_backups.items():
        try:
            jenkins_session.session.post(
                f"{jenkins_session.url}/job/{job_name}/config.xml",
                data=config.encode('utf-8'),
                auth=(jenkins_session.username, jenkins_session.password),
                headers={"Content-Type": "application/xml"}
            )
        except Exception:
            pass


@pytest.fixture(scope="function")
def cleanup_test_job(jenkins_session: Any) -> Generator[callable, None, None]:
    """
    Provide a function to cleanup test jobs created during testing.

    Args:
        jenkins_session: JenkinsSession instance

    Yields:
        Function that deletes specified job
    """
    jobs_to_delete = []

    def register_job(job_name: str) -> None:
        """Register job for cleanup."""
        jobs_to_delete.append(job_name)

    yield register_job

    for job_name in jobs_to_delete:
        try:
            jenkins_session.session.post(
                f"{jenkins_session.url}/job/{job_name}/doDelete",
                auth=(jenkins_session.username, jenkins_session.password)
            )
        except Exception:
            pass


@pytest.fixture(scope="session")
def exploit_registry() -> Any:
    """
    Get the CVE exploit registry.

    Returns:
        ExploitRegistry instance with all registered exploits
    """
    from jenkins_breaker.modules import exploit_registry
    return exploit_registry


@pytest.fixture(scope="function")
def capture_exploit_output() -> Generator[list, None, None]:
    """
    Capture exploit output for validation.

    Yields:
        List that captures output strings
    """
    output = []
    yield output


def pytest_configure(config):
    """
    Pytest configuration hook.

    Args:
        config: Pytest config object
    """
    config.addinivalue_line(
        "markers", "integration: Integration tests requiring Jenkins lab"
    )
    config.addinivalue_line(
        "markers", "unit: Unit tests not requiring external services"
    )
    config.addinivalue_line(
        "markers", "slow: Tests that take significant time"
    )
    config.addinivalue_line(
        "markers", "cve: CVE exploit module tests"
    )
    config.addinivalue_line(
        "markers", "postex: Post-exploitation tests"
    )
    config.addinivalue_line(
        "markers", "chain: Exploit chain tests"
    )


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add markers automatically.

    Args:
        config: Pytest config object
        items: List of collected test items
    """
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        if "test_exploits" in str(item.fspath):
            item.add_marker(pytest.mark.cve)
        if "test_postex" in str(item.fspath):
            item.add_marker(pytest.mark.postex)
        if "test_full_chain" in str(item.fspath) or "test_chain" in str(item.fspath):
            item.add_marker(pytest.mark.chain)
