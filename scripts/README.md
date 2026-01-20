# Scripts Directory

Local validation and utility scripts for JenkinsBreaker development.

## Local CI Pipeline

### `local_ci.sh` (Bash)

Comprehensive validation pipeline for Linux/macOS/WSL environments.

**Usage**:
```bash
# Full pipeline with automatic cleanup
./scripts/local_ci.sh

# Keep jenkins-lab running after tests
STOP_LAB=false ./scripts/local_ci.sh

# Skip cleanup entirely (debug mode)
CLEANUP=false ./scripts/local_ci.sh
```

**Pipeline Stages**:
1. Requirements check (Docker, Python)
2. Jenkins lab startup and health verification
3. Linting (Ruff)
4. Type checking (Mypy)
5. Unit tests (pytest)
6. Integration tests against jenkins-lab
7. Quick exploit validation
8. Secret scanning (Gitleaks)
9. Report generation

**Exit Codes**:
- `0`: All checks passed
- `1`: One or more failures

### `local_ci.ps1` (PowerShell)

Windows-native validation pipeline with identical functionality.

**Usage**:
```powershell
# Full pipeline
.\scripts\local_ci.ps1

# Skip Docker startup (if already running)
.\scripts\local_ci.ps1 -SkipDocker

# Keep jenkins-lab running
.\scripts\local_ci.ps1 -KeepRunning

# Skip integration tests (faster iteration)
.\scripts\local_ci.ps1 -SkipIntegration
```

**Parameters**:
- `-SkipDocker`: Don't start/stop jenkins-lab container
- `-SkipIntegration`: Skip integration tests (unit tests only)
- `-KeepRunning`: Leave jenkins-lab running after completion

## Environment Variables

Both scripts support:

- `JENKINS_URL`: Override jenkins-lab URL (default: http://localhost:8080)
- `JENKINS_USER`: Override admin username (default: admin)
- `JENKINS_PASS`: Override admin password (default: admin)

**Example**:
```bash
JENKINS_URL=http://192.168.1.100:8080 ./scripts/local_ci.sh
```

## Output

Both scripts generate `ci_report.txt` in the project root with detailed results:

```
JenkinsBreaker Local CI Report
Generated: [timestamp]

Environment:
- Jenkins Lab: http://localhost:8080
- Python: [version]
- Docker: [version]

Test Results:
- Linting: PASSED
- Type Checking: PASSED
- Unit Tests: PASSED
- Integration Tests: PASSED
- Secret Scanning: PASSED
```

## Integration with Pre-Commit

Run local CI before pushing:

```bash
# Install pre-commit hooks
pre-commit install

# Manual pre-commit check
pre-commit run --all-files

# Full CI validation
./scripts/local_ci.sh

# Commit if all checks pass
git commit -m "feat: add new CVE module"
git push
```

## Troubleshooting

**Jenkins lab won't start**:
```bash
cd jenkins-lab
docker-compose down -v
docker-compose up -d
```

**Port 8080 already in use**:
```bash
# Linux/macOS
lsof -i :8080
kill -9 [PID]

# Windows
netstat -ano | findstr :8080
taskkill /PID [PID] /F
```

**Type checking failures**:
```bash
# Clear mypy cache
rm -rf .mypy_cache
mypy --install-types src/jenkins_breaker/
```

**Integration tests timeout**:
- Increase timeout in `tests/conftest.py`
- Verify jenkins-lab is healthy: `curl -u admin:admin http://localhost:8080`

## Best Practices

1. **Run local CI before every commit**: Catch issues early
2. **Use pre-commit hooks**: Instant feedback on code quality
3. **Keep jenkins-lab running during development**: Faster test iterations
4. **Review ci_report.txt**: Detailed failure analysis
5. **Test new exploits individually first**: `pytest tests/integration/test_exploits.py::test_cve_XXXX -v`

## See Also

- `DEVELOPMENT.md` - Complete development guide
- `tests/README.md` - Testing documentation
- `jenkins-lab/README.md` - Lab environment setup
