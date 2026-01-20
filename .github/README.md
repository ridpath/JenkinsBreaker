# GitHub Configuration

## Automated Security Scanning: Intentionally Disabled

This repository contains security research tools designed for authorized penetration testing. Automated GitHub security features are intentionally limited or disabled to prevent false positives and operational noise.

### Configuration Status

**Dependabot**: Limited to monthly checks, 0 automated PRs
- File: `.github/dependabot.yml`
- Rationale: Exploit development requires specific dependency versions; automated updates can break exploits

**GitHub Actions**: Workflows directory present but empty
- File: `.github/workflows/.gitkeep`
- Rationale: CI/CD occurs locally via `scripts/local_ci.sh` to test against local jenkins-lab

**Advanced Security**: Should be disabled in repository settings
- Path: Settings → Security → Code security and analysis
- **CodeQL**: Disabled - triggers false positives on payload generators
- **Secret scanning**: Disabled or configured with `.gitleaksignore` - test credentials intentional
- **Dependabot security updates**: Disabled - manual review required

### Why Local Validation?

1. **Security Scanner False Positives**:
   - Exploit modules trigger "malicious code" alerts
   - Payload generators use subprocess/exec patterns
   - Reverse shell code flagged as malware

2. **Operational Security**:
   - Testing exploits against local infrastructure (jenkins-lab)
   - No external dependencies for validation
   - Faster feedback (2 seconds vs 2+ minutes)

3. **Professional Practice**:
   - Real exploit developers test on controlled infrastructure
   - Prevents accidental exposure of capabilities
   - Maintains GitHub repository in good standing

### Local Validation Tools

**Pre-Commit Hooks** (`.pre-commit-config.yaml`):
- Ruff: Linting and formatting
- Mypy: Type checking
- Bandit: Security scanning (exploit modules excluded)
- Gitleaks: Credential leak prevention

**Local CI Pipeline**:
- Bash: `./scripts/local_ci.sh`
- PowerShell: `.\scripts\local_ci.ps1`

### Repository Settings Checklist

Before pushing to GitHub, verify these settings:

1. Navigate to repository Settings
2. Security → Code security and analysis:
   - [ ] Dependency graph: Optional (useful for dependency tracking)
   - [ ] Dependabot alerts: Optional (manual review)
   - [ ] Dependabot security updates: **Disabled**
   - [ ] CodeQL analysis: **Disabled**
   - [ ] Secret scanning: **Disabled** (or configure .gitleaksignore)
3. Actions → General:
   - [ ] Actions permissions: Disabled or "Allow local actions only"

### Credential Management

**Test Credentials** (safe to commit in fixtures):
- Jenkins lab: admin/admin
- Documented in: `jenkins-lab/README.md`

**Real Credentials** (never commit):
- Use `.env` files (gitignored)
- Environment variables
- Password managers

**Gitleaks Configuration**:
- Pre-commit hook scans for secrets
- `.gitleaksignore` excludes known test credentials
- Manual scan: `gitleaks detect --source . --verbose`

### Compliance Statement

This repository contains tools for:
- Authorized penetration testing
- Red team exercises
- Security research
- CTF competitions

All code is provided for legal security testing only. Users are responsible for compliance with applicable laws and authorization requirements.

### Support

For questions about this configuration:
- Review: `DEVELOPMENT.md`
- Issues: https://github.com/ridpath/JenkinsBreaker/issues

**Note**: This is a security research tool. The disabled automated scanning is intentional and documented. If GitHub flags this repository, reference this README and the project's legitimate security research purpose.
