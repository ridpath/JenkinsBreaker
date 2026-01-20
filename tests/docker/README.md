# Jenkins Lab Docker Testing Infrastructure

This directory contains Docker-related testing infrastructure for JenkinsBreaker.

## Jenkins Lab Reset Scripts

Two reset scripts are provided for test isolation:

### Python Script (Recommended for Windows)

```bash
python jenkins-lab-reset.py
```

Cross-platform Python script that:
- Automatically detects Docker availability (local or WSL)
- Stops and removes jenkins-lab container
- Removes volumes for clean state
- Restarts container
- Waits for Jenkins to be ready

### Bash Script (Linux/macOS/WSL)

```bash
chmod +x jenkins-lab-reset.sh
./jenkins-lab-reset.sh
```

Bash script for Unix-like systems.

## Usage in pytest

The reset mechanism is integrated into pytest fixtures in `tests/conftest.py`.

### Manual Reset Between Test Sessions

```bash
# Reset before running integration tests
python tests/docker/jenkins-lab-reset.py

# Run integration tests
pytest tests/integration/ -v
```

### Automatic Reset (via fixture)

The `reset_jenkins_job` fixture in conftest.py provides job-level reset:

```python
def test_exploit(jenkins_session, reset_jenkins_job):
    reset_jenkins_job("test-job")
    # Run test that modifies test-job
    # Job will be restored to original state after test
```

## Jenkins Lab Location

The jenkins-lab Docker configuration is located at:
```
JenkinsBreaker/jenkins-lab/
```

The tests reference this location via relative paths from conftest.py.

## Verification

After reset, Jenkins should be available at:
- URL: http://localhost:8080
- Username: admin
- Password: admin

Verify with:
```bash
curl -u admin:admin http://localhost:8080/api/json
```

Or via WSL:
```bash
wsl -d parrot -- curl -u admin:admin http://localhost:8080/api/json
```
