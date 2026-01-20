# Quick Start Guide - Enhanced Jenkins Labs

## Option 1: Single Enhanced Lab (EASIEST - 11+ Exploits)

Perfect if you're running on Windows or have limited resources.

### Start
```bash
cd jenkins-lab
docker-compose up -d
```

**Access**: http://localhost:8080 (admin/admin)  
**Exploitable CVEs**: 11+  
**Resources**: 2GB RAM, 1 CPU core

---

## Option 2: Multi-Lab Environment (MAXIMUM COVERAGE - 25+ Exploits)

Best for WSL/Linux or if you have resources and want full coverage.

### Start All Three Labs
```powershell
# Windows PowerShell
cd jenkins-lab
docker compose -f docker-compose-multi.yml up -d
```

```bash
# WSL/Linux
cd jenkins-lab
docker-compose -f docker-compose-multi.yml up -d
```

**Access Points**:
- OLD Lab: http://localhost:8080 (admin/admin) - 11+ CVEs
- MID Lab: http://localhost:8081 (admin/admin) - 6+ CVEs
- NEW Lab: http://localhost:8082 (admin/admin) - 8+ CVEs

**Resources**: 6-8GB RAM, 3-4 CPU cores

---

## If You're Using WSL

Since you mounted the old lab in WSL yesterday, you can:

### Option A: Continue with Single Enhanced Lab
```bash
# From Windows
cd jenkins-lab
docker-compose down
docker-compose up -d

# Or from WSL
wsl -d parrot
cd /mnt/c/Users/Chogyam/.zenflow/worktrees/jenkinsbreaker-7cc4/jenkins-lab
docker-compose up -d
```

### Option B: Try Multi-Lab in WSL
```bash
# From WSL
wsl -d parrot
cd /mnt/c/Users/Chogyam/.zenflow/worktrees/jenkinsbreaker-7cc4/jenkins-lab
docker-compose -f docker-compose-multi.yml up -d
```

---

## Verify Labs Are Running

### Check Status
```bash
# Single lab
docker ps

# Multi-lab
docker-compose -f docker-compose-multi.yml ps
```

### Check Logs
```bash
# Single lab
docker logs jenkins-lab

# Multi-lab
docker logs jenkins-lab-old
docker logs jenkins-lab-mid
docker logs jenkins-lab-new
```

---

## Test With JenkinsBreaker

### Single Enhanced Lab
```bash
python -m jenkins_breaker --url http://localhost:8080 -u admin -p admin --auto
```

### Multi-Lab (Test Each)
```bash
# Test OLD
python -m jenkins_breaker --url http://localhost:8080 -u admin -p admin --auto

# Test MID
python -m jenkins_breaker --url http://localhost:8081 -u admin -p admin --auto

# Test NEW
python -m jenkins_breaker --url http://localhost:8082 -u admin -p admin --auto
```

---

## Troubleshooting

### Labs Won't Start

If you see errors about missing files:
```powershell
# Windows PowerShell
cd jenkins-lab
.\setup_multi_lab.ps1
```

```bash
# WSL/Linux
cd jenkins-lab
bash setup_multi_lab.sh
```

### Port 8080 Already in Use

The old lab is probably still running:
```bash
docker stop jenkins-lab
docker rm jenkins-lab

# Then start fresh
docker-compose up -d
```

### Still Not Working?

Clean everything and restart:
```bash
# Stop all containers
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)

# Remove volumes
docker volume prune -f

# Start fresh
cd jenkins-lab
docker-compose up -d
```

---

## What You Should See

### Single Enhanced Lab
When you run auto-exploit, you should see **11+ successful exploits**, including:
- CVE-2016-0792
- CVE-2017-1000353
- CVE-2018-1000861
- CVE-2018-1000402 ✓ NEW
- CVE-2018-1000600 ✓ NEW
- CVE-2019-1003000 ✓ NEW
- CVE-2019-1003001
- CVE-2019-1003029
- CVE-2019-1003040
- CVE-2019-10358 ✓ NEW
- CVE-2020-2249 ✓ NEW
- FEATURE-SCRIPT-CONSOLE
- FEATURE-JOB-CONFIG

### Multi-Lab
Each lab will show different exploits working based on its Jenkins version.

---

## Recommended Approach

1. **Start with single enhanced lab** (port 8080)
   - Easiest to set up
   - 11+ exploits working
   - Good for most testing

2. **If you need more coverage**, use multi-lab
   - All 3 labs running
   - 25+ total exploits
   - Complete CVE coverage

3. **Test from your existing WSL mount**
   - Should work fine
   - Just make sure old lab is stopped first

---

## Need Help?

Check these files:
- `README_MULTI_LAB.md` - Detailed multi-lab documentation
- `PLUGIN_VULNERABILITY_MAP.md` - CVE coverage details
- `README.md` - General Jenkins lab info

Or just ask!
