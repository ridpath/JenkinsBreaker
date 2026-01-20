# Local Validation Pipeline

This repository uses a **local-first validation** approach instead of GitHub Actions.

## Why Local Validation?

**Professional Exploit Development Practice**:
- Security research tools trigger false positives in automated scanners
- Testing exploits requires controlled infrastructure (jenkins-lab)
- Faster feedback: 2 seconds (pre-commit) vs 2+ minutes (GitHub Actions)
- No risk of repository flagging for "malicious code"

## Validation Layers

### Layer 1: Pre-Commit Hooks (Instant)

Runs automatically on `git commit`:

```bash
# Install (one-time)
pre-commit install

# Manual run
pre-commit run --all-files
```

**Checks**:
- **Ruff**: Linting and formatting
- **Mypy**: Type hint verification (strict mode)
- **Bandit**: Security scanning (exploit modules excluded)
- **Gitleaks**: Credential leak prevention
- **YAML validation**: Config syntax
- **Code cleanliness**: Trailing whitespace, EOF

**Configuration**: `.pre-commit-config.yaml`

### Layer 2: Local CI Pipeline (Comprehensive)

Full integration testing with jenkins-lab:

```bash
# Bash
./scripts/local_ci.sh

# PowerShell
.\scripts\local_ci.ps1
```

**Pipeline Stages**:
1. Requirements check (Docker, Python)
2. jenkins-lab startup and health verification
3. Linting validation
4. Type checking
5. Unit tests
6. Integration tests (live exploits against jenkins-lab)
7. Secret scanning
8. Report generation

**Output**: `ci_report.txt` with detailed results

## GitHub Configuration

**Automated Scanning Disabled**:
- CodeQL: OFF
- Secret scanning: OFF or configured with `.gitleaksignore`
- Dependabot: Monthly checks, 0 automated PRs

**Rationale**: Security research tool with intentional patterns that trigger false positives.

See `.github/README.md` for full details.

## Setup

```bash
# Automated setup
./scripts/setup_dev_environment.sh      # Bash
.\scripts\setup_dev_environment.ps1    # PowerShell

# Manual setup
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
cd jenkins-lab && docker-compose up -d
```

## Development Workflow

```bash
# 1. Make changes
vim src/jenkins_breaker/modules/new_exploit.py

# 2. Quick validation (2 seconds)
pre-commit run --all-files

# 3. Full validation (2-5 minutes)
./scripts/local_ci.sh

# 4. Commit (pre-commit runs automatically)
git commit -m "feat: add new exploit"

# 5. Push
git push
```

## Benefits

1. **No GitHub Noise**: Zero false positive alerts
2. **Zero Risk**: No repository suspension concerns
3. **Faster Development**: Instant pre-commit feedback
4. **True Security**: Gitleaks prevents actual credential leaks
5. **Professional**: Mirrors real exploit development practices

## Documentation

- **Full Guide**: `DEVELOPMENT.md`
- **Quick Reference**: `scripts/QUICK_REFERENCE.md`
- **Scripts Documentation**: `scripts/README.md`
- **GitHub Config**: `.github/README.md`

## Support

This is a legitimate security research tool for authorized testing. The local validation approach is intentional and follows industry best practices for exploit development.

For questions: Review `DEVELOPMENT.md` or open an issue.
