"""Build log mining for credential and secret extraction.

Extracts hardcoded credentials, API keys, database connection strings,
and other secrets from historical Jenkins build logs using pattern matching
and entropy analysis.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class LogSecret:
    """Represents a secret found in build logs."""
    type: str
    value: str
    job_name: str
    build_number: int
    context: str
    entropy: float = 0.0
    confidence: str = "low"


@dataclass
class LogMiningResult:
    """Result of log mining operation."""
    secrets: list[LogSecret]
    jobs_scanned: int
    builds_scanned: int
    total_log_size: int
    scan_duration: float = 0.0


class LogMiner:
    """Mine Jenkins build logs for secrets and credentials."""

    def __init__(self, session: Any):
        """Initialize log miner.

        Args:
            session: Authenticated Jenkins session for API access
        """
        self.session = session
        self.patterns = self._compile_patterns()
        self.secrets_found: list[LogSecret] = []

    def _compile_patterns(self) -> dict[str, re.Pattern]:
        """Compile regex patterns for secret detection.

        Returns:
            Dictionary of compiled patterns
        """
        return {
            "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "aws_secret_key": re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key[\'"\s:=]+([A-Za-z0-9/+=]{40})'),
            "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'),
            "slack_token": re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'),
            "slack_webhook": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}'),
            "generic_api_key": re.compile(r'(?i)api[_-]?key[\'"\s:=]+([\'"]?)([A-Za-z0-9_\-]{20,})\1'),
            "bearer_token": re.compile(r'(?i)bearer\s+([A-Za-z0-9_\-\.]+)'),
            "jwt": re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            "private_key": re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
            "password": re.compile(r'(?i)password[\'"\s:=]+([\'"]?)([^\s\'"]{8,})\1'),
            "db_connection": re.compile(r'(?i)(mysql|postgres|mongodb|redis)://([^:]+):([^@]+)@([^/\s]+)'),
            "jdbc_connection": re.compile(r'jdbc:[^:]+://[^:]+:[0-9]+/[^\s;]+;[^\s]*password=([^;\s]+)'),
            "docker_auth": re.compile(r'(?i)docker[_-]?password[\'"\s:=]+([\'"]?)([^\s\'"]+)\1'),
            "npm_token": re.compile(r'//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]+)'),
            "pypi_token": re.compile(r'pypi-[A-Za-z0-9_-]{59,}'),
            "google_api_key": re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
            "azure_key": re.compile(r'(?i)(?:azure|az)[_-]?(?:key|secret)[\'"\s:=]+([\'"]?)([A-Za-z0-9/+=]{40,})\1'),
            "sendgrid_key": re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
            "mailgun_key": re.compile(r'key-[0-9a-z]{32}'),
            "stripe_key": re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'),
            "twilio_key": re.compile(r'SK[0-9a-f]{32}'),
            "base64_creds": re.compile(r'(?i)(?:basic|authorization)[\'"\s:=]+([\'"]?)basic\s+([A-Za-z0-9+/=]{20,})\1', re.IGNORECASE),
        }

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            data: String to analyze

        Returns:
            Entropy value (0-8, higher = more random)
        """
        if not data:
            return 0.0

        entropy = 0.0
        for count in Counter(data).values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return entropy

    def is_high_entropy(self, data: str, threshold: float = 4.5) -> bool:
        """Check if string has high entropy (likely a secret).

        Args:
            data: String to check
            threshold: Entropy threshold

        Returns:
            True if entropy is above threshold
        """
        return self.calculate_entropy(data) > threshold

    def get_all_jobs(self) -> list[dict[str, Any]]:
        """Retrieve list of all jobs from Jenkins.

        Returns:
            List of job dictionaries with name and url
        """
        groovy_code = """
import jenkins.model.Jenkins

def jenkins = Jenkins.getInstance()
def jobs = jenkins.getAllItems(hudson.model.Job)

jobs.each { job ->
    println "JOB:" + job.getName() + "||" + job.getUrl()
}
"""

        result = self.session.execute_groovy(groovy_code)

        jobs = []
        for line in result.split('\n'):
            if line.startswith("JOB:"):
                parts = line[4:].split("||")
                if len(parts) == 2:
                    jobs.append({"name": parts[0].strip(), "url": parts[1].strip()})

        return jobs

    def get_job_builds(self, job_name: str, limit: int = 50) -> list[int]:
        """Get build numbers for a specific job.

        Args:
            job_name: Job name
            limit: Maximum number of builds to retrieve

        Returns:
            List of build numbers
        """
        groovy_code = f"""
import jenkins.model.Jenkins

def jenkins = Jenkins.getInstance()
def job = jenkins.getItem('{job_name}')

if (job == null) {{
    println "ERROR:Job not found"
    return
}}

def builds = job.getBuilds().limit({limit})
builds.each {{ build ->
    println "BUILD:" + build.getNumber()
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "ERROR" in result:
            return []

        build_numbers = []
        for line in result.split('\n'):
            if line.startswith("BUILD:"):
                try:
                    build_numbers.append(int(line[6:].strip()))
                except ValueError:
                    pass

        return build_numbers

    def get_build_log(self, job_name: str, build_number: int, max_lines: int = 10000) -> Optional[str]:
        """Retrieve build console log.

        Args:
            job_name: Job name
            build_number: Build number
            max_lines: Maximum lines to retrieve

        Returns:
            Console log text or None
        """
        groovy_code = f"""
import jenkins.model.Jenkins

def jenkins = Jenkins.getInstance()
def job = jenkins.getItem('{job_name}')

if (job == null) {{
    println "ERROR:Job not found"
    return
}}

def build = job.getBuildByNumber({build_number})

if (build == null) {{
    println "ERROR:Build not found"
    return
}}

try {{
    def logFile = build.getLogFile()
    if (!logFile.exists()) {{
        println "ERROR:Log file not found"
        return
    }}

    def lines = logFile.readLines()
    def maxLines = {max_lines}

    if (lines.size() > maxLines) {{
        lines = lines.take(maxLines)
    }}

    lines.each {{ line ->
        println line
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if result.startswith("ERROR"):
            return None

        return result

    def scan_log_content(self,
                        log_content: str,
                        job_name: str,
                        build_number: int) -> list[LogSecret]:
        """Scan log content for secrets.

        Args:
            log_content: Build log text
            job_name: Job name
            build_number: Build number

        Returns:
            List of found secrets
        """
        found_secrets = []

        for secret_type, pattern in self.patterns.items():
            for match in pattern.finditer(log_content):
                value = match.group(0)

                if secret_type in ["generic_api_key", "password", "azure_key", "base64_creds"]:
                    try:
                        value = match.group(2)
                    except IndexError:
                        value = match.group(0)

                if len(value) < 8:
                    continue

                start = max(0, match.start() - 50)
                end = min(len(log_content), match.end() + 50)
                context = log_content[start:end]

                entropy = self.calculate_entropy(value)

                confidence = "low"
                if entropy > 4.5:
                    confidence = "high"
                elif entropy > 3.5:
                    confidence = "medium"

                secret = LogSecret(
                    type=secret_type,
                    value=value,
                    job_name=job_name,
                    build_number=build_number,
                    context=context.replace('\n', ' '),
                    entropy=entropy,
                    confidence=confidence
                )

                found_secrets.append(secret)

        high_entropy_strings = self._find_high_entropy_strings(log_content)
        for value, context_str, entropy in high_entropy_strings:
            secret = LogSecret(
                type="high_entropy_string",
                value=value,
                job_name=job_name,
                build_number=build_number,
                context=context_str,
                entropy=entropy,
                confidence="medium"
            )
            found_secrets.append(secret)

        return found_secrets

    def _find_high_entropy_strings(self, text: str, min_length: int = 20) -> list[tuple[str, str, float]]:
        """Find high-entropy strings that might be secrets.

        Args:
            text: Text to scan
            min_length: Minimum string length to consider

        Returns:
            List of (value, context, entropy) tuples
        """
        results = []

        pattern = re.compile(r'[A-Za-z0-9+/=_\-]{20,}')

        for match in pattern.finditer(text):
            value = match.group(0)

            if len(value) < min_length or len(value) > 200:
                continue

            entropy = self.calculate_entropy(value)

            if entropy > 4.5:
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].replace('\n', ' ')

                results.append((value, context, entropy))

        return results

    def mine_job(self, job_name: str, build_limit: int = 50) -> list[LogSecret]:
        """Mine all builds of a specific job.

        Args:
            job_name: Job to mine
            build_limit: Maximum builds to scan

        Returns:
            List of found secrets
        """
        secrets = []

        build_numbers = self.get_job_builds(job_name, limit=build_limit)

        for build_number in build_numbers:
            log_content = self.get_build_log(job_name, build_number)

            if log_content:
                build_secrets = self.scan_log_content(log_content, job_name, build_number)
                secrets.extend(build_secrets)

        return secrets

    def mine_all_jobs(self,
                     job_limit: Optional[int] = None,
                     build_limit: int = 20) -> LogMiningResult:
        """Mine all jobs in Jenkins for secrets.

        Args:
            job_limit: Maximum jobs to scan (None = all)
            build_limit: Maximum builds per job

        Returns:
            LogMiningResult with all found secrets
        """
        import time
        start_time = time.time()

        jobs = self.get_all_jobs()

        if job_limit:
            jobs = jobs[:job_limit]

        all_secrets = []
        total_builds = 0
        total_log_size = 0

        for job in jobs:
            job_secrets = self.mine_job(job["name"], build_limit=build_limit)
            all_secrets.extend(job_secrets)

            build_count = len(self.get_job_builds(job["name"], limit=build_limit))
            total_builds += build_count

        duration = time.time() - start_time

        return LogMiningResult(
            secrets=all_secrets,
            jobs_scanned=len(jobs),
            builds_scanned=total_builds,
            total_log_size=total_log_size,
            scan_duration=duration
        )

    def deduplicate_secrets(self, secrets: list[LogSecret]) -> list[LogSecret]:
        """Remove duplicate secrets based on value.

        Args:
            secrets: List of secrets

        Returns:
            Deduplicated list
        """
        seen: set[str] = set()
        unique_secrets = []

        for secret in secrets:
            if secret.value not in seen:
                seen.add(secret.value)
                unique_secrets.append(secret)

        return unique_secrets


def mine_job_logs(session: Any,
                  job_name: str,
                  build_limit: int = 50) -> list[LogSecret]:
    """Quick function to mine a specific job.

    Args:
        session: Jenkins session
        job_name: Job to mine
        build_limit: Max builds to scan

    Returns:
        List of found secrets
    """
    miner = LogMiner(session)
    return miner.mine_job(job_name, build_limit)


def mine_all_logs(session: Any,
                  job_limit: Optional[int] = None,
                  build_limit: int = 20) -> LogMiningResult:
    """Quick function to mine all jobs.

    Args:
        session: Jenkins session
        job_limit: Max jobs to scan
        build_limit: Max builds per job

    Returns:
        LogMiningResult with findings
    """
    miner = LogMiner(session)
    return miner.mine_all_jobs(job_limit, build_limit)
