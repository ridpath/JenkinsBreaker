# Development Guide

JenkinsBreaker is a security research tool for authorized penetration testing and red team operations. This guide outlines the development workflow and local validation procedures.

## Development Philosophy

This project follows a **local-first validation** approach to maintain operational security:

- **Local Testing**: All exploit validation occurs on local infrastructure (jenkins-lab container)
- **No CI/CD Automation**: GitHub Actions disabled to prevent false positives from security scanners
- **Pre-Commit Validation**: Instant feedback via local hooks before code reaches remote repository
- **Controlled Dependency Updates**: Dependabot limited to monthly checks with no automated PRs

## Environment Setup

### Prerequisites

- Python 3.9+
- Docker and Docker Compose
- Git with pre-commit support

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/ridpath/JenkinsBreaker.git
cd JenkinsBreaker

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### Jenkins Lab Setup

The jenkins-lab environment provides a controlled testing target with planted credentials and vulnerabilities:

```bash
cd jenkins-lab
docker-compose up -d

# Verify Jenkins is accessible
curl -u admin:admin http://localhost:8080
```

**Credentials**: admin/admin
**URL**: http://localhost:8080

See `jenkins-lab/README.md` for detailed lab documentation.

## Local Validation Workflow

### Pre-Commit Hooks

Pre-commit hooks run automatically on `git commit` and provide instant validation:

**Checks Performed**:
- **Ruff**: Fast Python linting and formatting
- **Mypy**: Type hint verification (strict mode)
- **Bandit**: Security scanning (excludes exploit modules intentionally)
- **Gitleaks**: Credential leak prevention
- **YAML validation**: Config file syntax checking
- **Trailing whitespace**: Code cleanliness

**Manual Execution**:
```bash
# Run all hooks on all files
pre-commit run --all-files

# Run specific hook
pre-commit run ruff --all-files
pre-commit run mypy --all-files

# Bypass hooks (emergency use only)
git commit --no-verify
```

**Bandit Configuration**: The security scanner intentionally ignores:
- `src/jenkins_breaker/modules/` - Exploit code triggers false positives
- `src/jenkins_breaker/payloads/` - Payload generators use subprocess/exec patterns
- `exploits/` - Legacy exploit modules

### Local CI Pipeline

The local CI pipeline replicates full integration testing without relying on GitHub infrastructure.

#### Bash (Linux/macOS/WSL)

```bash
# Full pipeline with cleanup
./scripts/local_ci.sh

# Keep jenkins-lab running after tests
STOP_LAB=false ./scripts/local_ci.sh

# Skip cleanup entirely
CLEANUP=false ./scripts/local_ci.sh
```

#### PowerShell (Windows)

```powershell
# Full pipeline
.\scripts\local_ci.ps1

# Skip Docker startup (if jenkins-lab already running)
.\scripts\local_ci.ps1 -SkipDocker

# Keep jenkins-lab running
.\scripts\local_ci.ps1 -KeepRunning

# Skip integration tests (faster iteration)
.\scripts\local_ci.ps1 -SkipIntegration
```

#### Pipeline Stages

1. **Requirements Check**: Verify Docker, Python, and dependencies
2. **Jenkins Lab Startup**: Launch and health-check target environment
3. **Linting**: Ruff code quality checks
4. **Type Checking**: Mypy static analysis
5. **Unit Tests**: Fast isolated tests
6. **Integration Tests**: Live exploit validation against jenkins-lab
7. **Secret Scanning**: Gitleaks credential leak detection
8. **Report Generation**: Detailed results in `ci_report.txt`

**Exit Codes**:
- `0`: All checks passed
- `1`: One or more failures

## Development Workflows

### Adding a New CVE Module

1. **Research the vulnerability**:
   - Verify CVE details from NVD
   - Locate public exploits or PoC code
   - Identify affected Jenkins versions

2. **Create module file**:
   ```bash
   # Create new module
   touch src/jenkins_breaker/modules/cve_YYYY_XXXXX.py
   ```

3. **Implement ExploitModule interface**:
   ```python
   from jenkins_breaker.modules.base import ExploitModule, ExploitMetadata, ExploitResult
   from typing import Any
   
   class CVE_YYYY_XXXXX(ExploitModule):
       CVE_ID = "CVE-YYYY-XXXXX"
       METADATA = ExploitMetadata(
           cve_id="CVE-YYYY-XXXXX",
           name="Descriptive Name",
           description="Brief technical description",
           affected_versions=["< X.XXX"],
           mitre_attack=["T1059.006"],
           severity="critical",
           references=["https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXXX"],
           requires_auth=True,
           requires_crumb=False,
       )
       
       def run(self, session: Any, **kwargs) -> ExploitResult:
           try:
               # Exploitation logic here
               return ExploitResult(
                   exploit=self.CVE_ID,
                   status="success",
                   details="Exploitation successful"
               )
           except Exception as e:
               return ExploitResult(
                   exploit=self.CVE_ID,
                   status="error",
                   details=f"Failed: {str(e)}",
                   error=str(e)
               )
   ```

4. **Test the module**:
   ```bash
   # Quick test against jenkins-lab
   python tests/quick_exploit_test.py --cve CVE-YYYY-XXXXX
   
   # Integration test
   pytest tests/integration/test_exploits.py::test_cve_YYYY_XXXXX -v
   ```

5. **Document the module**:
   - Add entry to `docs/modules.md`
   - Update README.md CVE count
   - Include usage example

6. **Run local validation**:
   ```bash
   # Pre-commit checks
   pre-commit run --all-files
   
   # Full CI pipeline
   ./scripts/local_ci.sh
   ```

### Testing Payloads

```bash
# Test reverse shell generation
python -c "from jenkins_breaker.payloads.reverse_shell import generate_bash_shell; print(generate_bash_shell('10.10.14.5', 4444))"

# Test meterpreter (requires msfvenom)
python -c "from jenkins_breaker.payloads.meterpreter import generate_meterpreter; print(generate_meterpreter('10.10.14.5', 4444))"

# Test PowerShell payloads
python -c "from jenkins_breaker.payloads.powershell import generate_powershell_shell; print(generate_powershell_shell('10.10.14.5', 4444))"
```

### Testing Credential Extraction

```bash
# Extract all credentials from jenkins-lab
python -m jenkins_breaker postex credentials --target http://localhost:8080 --user admin --pass admin

# Test specific credential types
pytest tests/integration/test_postex.py::test_aws_credentials -v
pytest tests/integration/test_postex.py::test_ssh_keys -v
```

### Running the TUI/WebUI

```bash
# Terminal UI
python launch_tui.py

# Web UI (http://localhost:5000)
python launch_webui.py
```

## Code Quality Standards

### Type Hints

All production code must include type hints:

```python
from typing import Dict, List, Optional, Any

def exploit_target(url: str, credentials: Optional[Dict[str, str]] = None) -> ExploitResult:
    pass
```

**Verification**: `mypy src/jenkins_breaker/`

### Linting

Follow Ruff formatting and linting rules defined in `pyproject.toml`:

```bash
# Auto-fix issues
ruff check src/ --fix

# Format code
ruff format src/
```

### Testing

- **Unit Tests**: Fast, isolated, no external dependencies
- **Integration Tests**: Require jenkins-lab, marked with `@pytest.mark.integration`
- **Coverage Target**: 80%+

```bash
# Run with coverage
pytest tests/ --cov=jenkins_breaker --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS/Linux
start htmlcov/index.html  # Windows
```

## Security Considerations

### GitHub Repository Settings

**CRITICAL**: Disable automated security scanning to prevent false positives:

1. Navigate to repository Settings → Security
2. **Advanced Security**: Disabled
3. **CodeQL analysis**: Disabled
4. **Secret scanning**: Disabled (or configure `.gitleaksignore`)
5. **Dependabot**: Limited to monthly checks with 0 PR limit

**Rationale**: This is a security research tool. Exploit modules and payload generators intentionally trigger security scanners. Validation occurs locally via pre-commit hooks and `local_ci.sh`.

### Credential Management

**Never commit real credentials**:
- Use `.env` files (gitignored)
- Store in password managers
- Use environment variables

**Test credentials** (jenkins-lab only):
- Username: `admin`
- Password: `admin`
- These are documented and safe to commit in test fixtures

**Gitleaks Protection**:
- Pre-commit hook scans for secrets
- `.gitleaksignore` excludes known test credentials
- Manual scan: `gitleaks detect --source . --verbose`

### Exploit Development Ethics

This tool is for **authorized security testing only**:
- Penetration testing with written authorization
- Red team exercises
- CTF competitions
- Security research in controlled environments

**Prohibited Uses**:
- Unauthorized access to systems
- Malicious attacks
- Distribution of exploits for illegal purposes

## Troubleshooting

### Pre-Commit Hook Failures

**Mypy errors**:
```bash
# Regenerate mypy cache
mypy --install-types src/jenkins_breaker/
```

**Bandit false positives on new exploit**:
```bash
# Add to pyproject.toml [tool.ruff.lint.per-file-ignores]
"src/jenkins_breaker/modules/cve_YYYY_XXXXX.py" = ["S"]
```

### Jenkins Lab Issues

**Container won't start**:
```bash
docker-compose down
docker-compose up -d --force-recreate
```

**Credentials not working**:
```bash
# Reset jenkins-lab
cd jenkins-lab
docker-compose down -v
docker-compose up -d
```

**Port 8080 in use**:
```bash
# Find process using port
netstat -ano | findstr :8080  # Windows
lsof -i :8080  # Linux/macOS
```

### Integration Test Failures

**Jenkins not ready**:
- Increase timeout in `conftest.py`
- Manually verify: `curl -u admin:admin http://localhost:8080`

**Exploit module not found**:
```bash
# Verify module registration
python tests/check_registry.py
```

## Additional Resources

- **Module Documentation**: `docs/modules.md`
- **Jenkins Lab Guide**: `jenkins-lab/README.md`
- **Secrets Extraction**: `SECRETS_EXTRACTION_GUIDE.md`
- **UI Implementation**: `UI_IMPLEMENTATION.md`
- **Contributing**: `CONTRIBUTING.md`

## Support

For issues or questions:
- GitHub Issues: https://github.com/ridpath/JenkinsBreaker/issues
- Documentation: `docs/`

**Disclaimer**: This tool is provided for legal security testing only. Users are responsible for compliance with applicable laws and regulations.
