# Multi-Version Jenkins Lab - Maximum Vulnerability Coverage

## Overview

This enhanced lab provides THREE Jenkins instances, each targeting different CVE ranges to maximize exploit coverage.

## Lab Instances

### Jenkins Lab OLD (Port 8080)
- **Version**: Jenkins 2.138.3
- **Target CVEs**: 2016-2019
- **Exploitable CVEs**: 11+

### Jenkins Lab MID (Port 8081)
- **Version**: Jenkins 2.275
- **Target CVEs**: 2020-2021
- **Exploitable CVEs**: 6+

### Jenkins Lab NEW (Port 8082)
- **Version**: Jenkins 2.442
- **Target CVEs**: 2022-2024
- **Exploitable CVEs**: 8+

**Total Exploitable CVEs: 25+ across all labs**

## Quick Start

### Start All Labs
```bash
docker-compose -f docker-compose-multi.yml up -d
```

### Start Individual Labs
```bash
# OLD lab only
docker-compose -f docker-compose-multi.yml up -d jenkins-old

# MID lab only
docker-compose -f docker-compose-multi.yml up -d jenkins-mid

# NEW lab only
docker-compose -f docker-compose-multi.yml up -d jenkins-new
```

### Access Points

| Lab | URL | Credentials | Exploits |
|-----|-----|-------------|----------|
| OLD | http://localhost:8080 | admin/admin | 11+ CVEs |
| MID | http://localhost:8081 | admin/admin | 6+ CVEs |
| NEW | http://localhost:8082 | admin/admin | 8+ CVEs |

## CVE Coverage Matrix

### OLD Lab (2.138.3) - Port 8080

**Exploitable CVEs (11+)**:
1. CVE-2016-0792 - XStream Deserialization RCE
2. CVE-2017-1000353 - CLI Java Deserialization RCE
3. CVE-2018-1000861 - Jenkins Core Stapler RCE
4. CVE-2018-1000402 - AWS CodeDeploy Credential Exposure
5. CVE-2018-1000600 - GitHub Plugin File Read
6. CVE-2019-1003000 - Script Security AST Bypass
7. CVE-2019-1003001 - Pipeline Groovy Sandbox Bypass
8. CVE-2019-1003029 - Script Security Groovy RCE
9. CVE-2019-1003040 - Script Security Constructor Bypass
10. CVE-2019-10358 - Maven Plugin Credential Disclosure
11. CVE-2020-2249 - TFS Plugin Credential Exposure
12. FEATURE-SCRIPT-CONSOLE - Authenticated RCE
13. FEATURE-JOB-CONFIG - Job Configuration Injection

### MID Lab (2.275) - Port 8081

**Exploitable CVEs (6+)**:
1. CVE-2020-2100 - Git Plugin Resource Exhaustion
2. CVE-2021-21602 - Workspace File Read
3. CVE-2021-21686 - Agent-to-Controller Path Traversal
4. CVE-2022-30945 - Pipeline Groovy OS Command Injection
5. CVE-2022-34177 - Pipeline Input Step Path Traversal
6. CVE-2022-43401 - Pipeline Groovy Sandbox Bypass
7. FEATURE-SCRIPT-CONSOLE - Authenticated RCE
8. FEATURE-JOB-CONFIG - Job Configuration Injection

### NEW Lab (2.442) - Port 8082

**Exploitable CVEs (8+)**:
1. CVE-2023-24422 - Script Security Plugin Sandbox Bypass
2. CVE-2023-27903 - Credential Exposure via Webhook
3. CVE-2024-23897 - CLI Arbitrary File Read
4. CVE-2024-34144 - Script Security Sandbox Bypass
5. CVE-2024-43044 - Agent Arbitrary File Read to RCE
6. CVE-2024-47803 - Multi-Line Secret Exposure
7. CVE-2025-31722 - Templating Engine Plugin RCE
8. FEATURE-SCRIPT-CONSOLE - Authenticated RCE
9. FEATURE-JOB-CONFIG - Job Configuration Injection

## Testing Against Specific Lab

### Using JenkinsBreaker CLI

```bash
# Test against OLD lab
python -m jenkins_breaker --url http://localhost:8080 --username admin --password admin --auto

# Test against MID lab
python -m jenkins_breaker --url http://localhost:8081 --username admin --password admin --auto

# Test against NEW lab
python -m jenkins_breaker --url http://localhost:8082 --username admin --password admin --auto
```

### Using TUI

```bash
# Launch TUI and manually specify target
python launch_tui.py

# In TUI, set target URL:
# - http://localhost:8080 for OLD
# - http://localhost:8081 for MID
# - http://localhost:8082 for NEW
```

### Using Web UI

```bash
python launch_webui.py

# Access http://localhost:5000
# Add targets:
# - http://localhost:8080
# - http://localhost:8081
# - http://localhost:8082
```

## Resource Usage

### All Labs Running
- CPU: 3-4 cores
- RAM: 6-8 GB
- Disk: 3 GB

### Single Lab Running
- CPU: 1 core
- RAM: 2 GB
- Disk: 1 GB

## Management Commands

### Stop All Labs
```bash
docker-compose -f docker-compose-multi.yml down
```

### Reset All Labs (Clean State)
```bash
docker-compose -f docker-compose-multi.yml down -v
docker-compose -f docker-compose-multi.yml up -d
```

### View Logs
```bash
# All labs
docker-compose -f docker-compose-multi.yml logs -f

# Specific lab
docker logs -f jenkins-lab-old
docker logs -f jenkins-lab-mid
docker logs -f jenkins-lab-new
```

### Check Status
```bash
docker-compose -f docker-compose-multi.yml ps
```

## Network Configuration

All labs share the same Docker network (`jenkins-network`), allowing:
- Cross-lab lateral movement testing
- Multi-hop exploitation chains
- Container-to-container pivoting

## Security Considerations

**CRITICAL**: These labs contain intentionally vulnerable software.

- Run ONLY in isolated environments
- Do NOT expose to external networks
- Use firewall rules to restrict access
- Consider running in dedicated VMs

## Troubleshooting

### Port Already in Use

If port 8080 is already in use:
```bash
# Use only MID and NEW labs
docker-compose -f docker-compose-multi.yml up -d jenkins-mid jenkins-new
```

### Container Won't Start

```bash
# Check logs
docker logs jenkins-lab-old

# Rebuild
docker-compose -f docker-compose-multi.yml build jenkins-old
docker-compose -f docker-compose-multi.yml up -d jenkins-old
```

### High Memory Usage

Run labs individually instead of all at once:
```bash
# Stop all
docker-compose -f docker-compose-multi.yml down

# Start only needed lab
docker-compose -f docker-compose-multi.yml up -d jenkins-old
```

## Automated Testing

### Test All Labs
```bash
#!/bin/bash

# Test OLD lab
echo "Testing OLD lab (port 8080)..."
python -m jenkins_breaker --url http://localhost:8080 -u admin -p admin --auto

# Test MID lab
echo "Testing MID lab (port 8081)..."
python -m jenkins_breaker --url http://localhost:8081 -u admin -p admin --auto

# Test NEW lab
echo "Testing NEW lab (port 8082)..."
python -m jenkins_breaker --url http://localhost:8082 -u admin -p admin --auto
```

## Exploit Count Summary

- **OLD Lab**: 11+ exploits working
- **MID Lab**: 6+ exploits working
- **NEW Lab**: 8+ exploits working
- **Total**: 25+ unique CVE exploits testable

This provides maximum coverage for red team training, CVE research, and tool development.
