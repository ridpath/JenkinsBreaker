# JenkinsBreaker Test Suite

Comprehensive testing infrastructure for JenkinsBreaker offensive security framework.

## Test Structure

```
tests/
├── conftest.py                    # Pytest fixtures and configuration
├── unit/                          # Unit tests (no external dependencies)
│   ├── test_session.py
│   ├── test_auth.py
│   ├── test_payloads.py
│   └── test_chain.py
├── integration/                   # Integration tests (require jenkins-lab)
│   ├── test_exploits.py          # All 27 CVE exploit modules
│   ├── test_postex.py            # Post-exploitation credential extraction
│   └── test_full_chain.py        # End-to-end attack chains
├── docker/                        # Docker testing infrastructure
│   ├── jenkins-lab-reset.py      # Lab reset script (Python)
│   ├── jenkins-lab-reset.sh      # Lab reset script (Bash)
│   └── README.md
├── data/                          # Test data (extracted secrets, etc.)
├── test_jenkins_connection.py    # Quick connection verification
└── quick_exploit_test.py         # Quick smoke test
```
 Note: Legacy Path References**
> 
> Some standalone test scripts contain hardcoded legacy paths from development. These scripts work correctly when the package is installed via `pip install -e ".[dev]"`, but the hardcoded `sys.path.insert()` lines can be safely removed.
> 
> **Files with legacy paths:**
> - `tests/check_registry.py` - Quick registry verification
> - `tests/quick_exploit_test.py` - Quick smoke test (used in CI)
> - `tests/verify_exploits.py` - Manual exploit verification
> - `tests/test_jenkins_connection.py` - Connection test
> - `tests/identify_plugin_requirements.py` - Plugin requirement analysis
> - `tests/test_cli_launch.py` - CLI launch test
> - `tests/test_console_commands.py` - Console command test
> - `tests/test_core_functionality.py` - Core function test
> - `tests/test_enumeration.py` - Enumeration test
> - `tests/test_imports.py` - Import test
> 
> **Recommended action:** Remove `sys.path.insert(0, ...)` lines from these files. The proper Python path is automatically configured when using the installation methods above.


## Prerequisites

### Jenkins Lab (Required for Integration Tests)

The integration tests require jenkins-lab Docker container running at http://localhost:8080.

**Start jenkins-lab:**
```bash
cd ../jenkins-lab
docker-compose up -d
```

Or via WSL:
```bash
wsl -d parrot -- bash -c "cd /mnt/c/Users/Chogyam/.zenflow/worktrees/breakapart-db88/JenkinsBreaker/jenkins-lab && docker-compose up -d"
```

**Verify Jenkins is ready:**
```bash
python tests/test_jenkins_connection.py
```

### Python Dependencies

Install test dependencies:
```bash
pip install pytest pytest-cov pytest-asyncio requests
```

Or install all dev dependencies:
```bash
pip install -e ".[dev]"
```

## Running Tests

### Quick Smoke Test

Verify basic functionality:
```bash
python tests/quick_exploit_test.py
```

### Unit Tests Only

Run unit tests without external dependencies:
```bash
pytest tests/unit/ -v
```

### Integration Tests (Requires Jenkins Lab)

Run all integration tests:
```bash
pytest tests/integration/ -v
```

Run specific integration test class:
```bash
pytest tests/integration/test_exploits.py::TestCVEExploits -v
```

Run single exploit test:
```bash
pytest tests/integration/test_exploits.py::TestCVEExploits::test_cve_2024_23897_file_read -v
```

### Full Test Suite

Run all tests with coverage:
```bash
pytest tests/ -v --cov=src/jenkins_breaker --cov-report=html
```

### Test Markers

Tests are organized by markers:

- `@pytest.mark.unit` - Unit tests (fast, no external dependencies)
- `@pytest.mark.integration` - Integration tests (require jenkins-lab)
- `@pytest.mark.cve` - CVE exploit module tests
- `@pytest.mark.postex` - Post-exploitation tests
- `@pytest.mark.chain` - Exploit chain tests
- `@pytest.mark.slow` - Slow tests (> 10 seconds)

**Run only unit tests:**
```bash
pytest -m unit -v
```

**Run only CVE tests:**
```bash
pytest -m cve -v
```

**Exclude slow tests:**
```bash
pytest -m "not slow" -v
```

## Test Configuration

### Environment Variables

Override default test configuration:

```bash
export JENKINS_URL=http://localhost:8080
export JENKINS_USER=admin
export JENKINS_PASS=admin
export JENKINS_CONTAINER=jenkins-lab
export WSL_DISTRO=parrot

pytest tests/integration/ -v
```

### Pytest Configuration

See `pytest.ini` or `pyproject.toml` for pytest settings.

## Test Isolation

### Lab Reset Between Test Sessions

Reset jenkins-lab to clean state:
```bash
python tests/docker/jenkins-lab-reset.py
```

### Automatic Job Reset

The `reset_jenkins_job` fixture automatically backs up and restores job configurations:

```python
def test_job_modification(jenkins_session, reset_jenkins_job):
    reset_jenkins_job("my-job")
    # Modify job
    # Job automatically restored after test
```

## Planted Test Data

Jenkins-lab contains planted credentials for validation:

- **AWS**: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
- **SSH**: /home/jenkins/.ssh/id_rsa
- **NPM**: npm_ExampleTokenString123456789
- **Docker**: dockeruser / dockerpassword123
- **GitHub**: ghp_ExampleTokenString123456789ABC
- **Database**: dbadmin / DB_@dm1n_P@ssw0rd_2024!

See `../jenkins-lab/SECRETS_REFERENCE.md` for complete listing.

## Test Coverage Goals

- **Unit tests**: 80%+ coverage
- **Integration tests**: All 27 CVE modules tested
- **Post-exploitation**: All credential types validated
- **Chains**: All predefined chains tested

## Continuous Integration

### Local CI Pipeline

Run the same checks as CI:
```bash
# Linting
ruff check src/ tests/

# Type checking
mypy src/

# Tests
pytest tests/ -v --cov=src/jenkins_breaker

# Coverage threshold
pytest tests/ --cov=src/jenkins_breaker --cov-fail-under=80
```

## Troubleshooting

### Jenkins Not Accessible

```
[!] Cannot connect to Jenkins at http://localhost:8080
```

**Solution:**
```bash
# Check container status
docker ps | grep jenkins

# Start container
cd ../jenkins-lab && docker-compose up -d

# Check logs
docker logs jenkins-lab

# Verify Jenkins is ready
python tests/test_jenkins_connection.py
```

### Import Errors

```
ModuleNotFoundError: No module named 'jenkins_breaker'
```

**Solution:**
```bash
# Install in editable mode
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/path/to/JenkinsBreaker/src"
```

### Test Failures Due to Jenkins State

If tests fail due to modified Jenkins state:
```bash
# Reset jenkins-lab to clean state
python tests/docker/jenkins-lab-reset.py

# Re-run tests
pytest tests/integration/ -v
```

## Test Development

### Adding New Tests

1. **Unit test**: Add to `tests/unit/test_<module>.py`
2. **CVE exploit test**: Add to `tests/integration/test_exploits.py`
3. **Post-ex test**: Add to `tests/integration/test_postex.py`
4. **Chain test**: Add to `tests/integration/test_full_chain.py`

### Test Template

```python
import pytest
from typing import Any


@pytest.mark.integration
@pytest.mark.cve
def test_new_cve_exploit(jenkins_session: Any):
    """Test CVE-XXXX-XXXXX exploit."""
    from jenkins_breaker.modules import exploit_registry
    
    exploit = exploit_registry.get('CVE-XXXX-XXXXX')
    assert exploit is not None
    
    result = exploit.run(jenkins_session, param="value")
    
    assert result.status in ["success", "error"]
```

## Performance

Typical test execution times:

- **Unit tests**: ~2 seconds (12 tests)
- **Integration tests**: ~60 seconds (27 CVE tests + postex + chains)
- **Full suite**: ~90 seconds

## References

- pytest documentation: https://docs.pytest.org/
- pytest fixtures: https://docs.pytest.org/en/stable/fixture.html
- pytest markers: https://docs.pytest.org/en/stable/example/markers.html
