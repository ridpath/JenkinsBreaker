"""JSON report generation for JenkinsBreaker findings.

Provides structured JSON output for programmatic consumption and integration
with other tools.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Optional


@dataclass
class JSONReport:
    """Structured JSON report."""
    timestamp: str
    target: str
    jenkins_version: Optional[str]
    findings: list[dict[str, Any]]
    credentials: list[dict[str, Any]]
    vulnerabilities: list[dict[str, Any]]
    persistence: list[dict[str, Any]]
    lateral_movement: list[dict[str, Any]]
    recommendations: list[str]
    metadata: dict[str, Any]


class JSONReporter:
    """Generates JSON reports for exploitation findings."""

    def __init__(self):
        """Initialize JSON reporter."""
        self.findings: list[dict[str, Any]] = []
        self.credentials: list[dict[str, Any]] = []
        self.vulnerabilities: list[dict[str, Any]] = []
        self.persistence: list[dict[str, Any]] = []
        self.lateral_movement: list[dict[str, Any]] = []

    def add_finding(
        self,
        category: str,
        severity: str,
        title: str,
        description: str,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add a finding to the report.

        Args:
            category: Finding category
            severity: Severity level (critical, high, medium, low)
            title: Finding title
            description: Detailed description
            details: Optional additional details
        """
        self.findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        })

    def add_vulnerability(
        self,
        cve_id: str,
        name: str,
        severity: str,
        status: str,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add vulnerability to report.

        Args:
            cve_id: CVE identifier
            name: Vulnerability name
            severity: Severity level
            status: Exploitation status (exploited, vulnerable, not_vulnerable)
            details: Optional details
        """
        self.vulnerabilities.append({
            "cve_id": cve_id,
            "name": name,
            "severity": severity,
            "status": status,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        })

    def add_credential(
        self,
        credential_type: str,
        source: str,
        username: Optional[str] = None,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add credential to report.

        Args:
            credential_type: Type of credential
            source: Source location
            username: Optional username
            details: Optional additional details
        """
        self.credentials.append({
            "type": credential_type,
            "source": source,
            "username": username,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        })

    def add_persistence(
        self,
        method: str,
        status: str,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add persistence mechanism to report.

        Args:
            method: Persistence method
            status: Installation status
            details: Optional details
        """
        self.persistence.append({
            "method": method,
            "status": status,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        })

    def add_lateral_movement(
        self,
        target: str,
        method: str,
        status: str,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add lateral movement attempt to report.

        Args:
            target: Target host/service
            method: Movement method
            status: Attempt status
            details: Optional details
        """
        self.lateral_movement.append({
            "target": target,
            "method": method,
            "status": status,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        })

    def generate(
        self,
        target: str,
        jenkins_version: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None
    ) -> str:
        """Generate JSON report.

        Args:
            target: Target Jenkins URL
            jenkins_version: Jenkins version
            metadata: Optional metadata

        Returns:
            JSON report string
        """
        report = JSONReport(
            timestamp=datetime.utcnow().isoformat(),
            target=target,
            jenkins_version=jenkins_version,
            findings=self.findings,
            credentials=self.credentials,
            vulnerabilities=self.vulnerabilities,
            persistence=self.persistence,
            lateral_movement=self.lateral_movement,
            recommendations=self._generate_recommendations(),
            metadata=metadata or {}
        )

        return json.dumps(asdict(report), indent=2)

    def save(
        self,
        filename: str,
        target: str,
        jenkins_version: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None
    ) -> None:
        """Save JSON report to file.

        Args:
            filename: Output filename
            target: Target Jenkins URL
            jenkins_version: Jenkins version
            metadata: Optional metadata
        """
        report_json = self.generate(target, jenkins_version, metadata)

        with open(filename, 'w') as f:
            f.write(report_json)

    def _generate_recommendations(self) -> list[str]:
        """Generate recommendations based on findings.

        Returns:
            List of recommendation strings
        """
        recommendations = []

        if self.vulnerabilities:
            recommendations.append("Update Jenkins to the latest version to patch identified vulnerabilities")

        if any(v.get("severity") == "critical" for v in self.vulnerabilities):
            recommendations.append("Immediately patch critical vulnerabilities")

        if self.credentials:
            recommendations.append("Rotate all exposed credentials immediately")
            recommendations.append("Implement secrets management solution")

        if any(f.get("category") == "authentication" for f in self.findings):
            recommendations.append("Enable and enforce authentication for all endpoints")
            recommendations.append("Implement multi-factor authentication")

        if self.persistence:
            recommendations.append("Audit system for unauthorized persistence mechanisms")
            recommendations.append("Review cron jobs, startup scripts, and systemd services")

        if self.lateral_movement:
            recommendations.append("Implement network segmentation")
            recommendations.append("Review and restrict SSH key access")

        recommendations.extend([
            "Enable audit logging and monitoring",
            "Implement principle of least privilege",
            "Regular security assessments and penetration testing",
            "Deploy security plugins and hardening configurations"
        ])

        return recommendations


def create_json_report(
    target: str,
    findings: Optional[list[dict[str, Any]]] = None,
    credentials: Optional[list[dict[str, Any]]] = None,
    vulnerabilities: Optional[list[dict[str, Any]]] = None,
    jenkins_version: Optional[str] = None
) -> str:
    """Factory function to create JSON report.

    Args:
        target: Target Jenkins URL
        findings: Optional list of findings
        credentials: Optional list of credentials
        vulnerabilities: Optional list of vulnerabilities
        jenkins_version: Optional Jenkins version

    Returns:
        JSON report string
    """
    reporter = JSONReporter()

    if findings:
        for finding in findings:
            reporter.add_finding(**finding)

    if credentials:
        for cred in credentials:
            reporter.add_credential(**cred)

    if vulnerabilities:
        for vuln in vulnerabilities:
            reporter.add_vulnerability(**vuln)

    return reporter.generate(target, jenkins_version)
