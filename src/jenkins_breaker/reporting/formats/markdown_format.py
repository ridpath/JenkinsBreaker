"""Markdown report generation for human-readable documentation.

Provides Markdown-formatted reports with sections, tables, and detailed
findings for easy reading and sharing.
"""

from datetime import datetime
from typing import Any, Optional


class MarkdownReporter:
    """Generates Markdown reports for exploitation findings."""

    def __init__(self):
        """Initialize Markdown reporter."""
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
        """Add a finding to the report."""
        self.findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "details": details or {}
        })

    def add_vulnerability(
        self,
        cve_id: str,
        name: str,
        severity: str,
        status: str,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add vulnerability to report."""
        self.vulnerabilities.append({
            "cve_id": cve_id,
            "name": name,
            "severity": severity,
            "status": status,
            "details": details or {}
        })

    def add_credential(
        self,
        credential_type: str,
        source: str,
        username: Optional[str] = None,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add credential to report."""
        self.credentials.append({
            "type": credential_type,
            "source": source,
            "username": username,
            "details": details or {}
        })

    def add_persistence(
        self,
        method: str,
        status: str,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add persistence mechanism to report."""
        self.persistence.append({
            "method": method,
            "status": status,
            "details": details or {}
        })

    def add_lateral_movement(
        self,
        target: str,
        method: str,
        status: str,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        """Add lateral movement attempt to report."""
        self.lateral_movement.append({
            "target": target,
            "method": method,
            "status": status,
            "details": details or {}
        })

    def _generate_executive_summary(self, target: str, jenkins_version: Optional[str]) -> str:
        """Generate executive summary section."""
        summary = "## Executive Summary\n\n"
        summary += f"**Target:** {target}\n\n"

        if jenkins_version:
            summary += f"**Jenkins Version:** {jenkins_version}\n\n"

        summary += f"**Assessment Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"

        critical_vulns = sum(1 for v in self.vulnerabilities if v["severity"].lower() == "critical")
        high_vulns = sum(1 for v in self.vulnerabilities if v["severity"].lower() == "high")

        summary += "### Summary Statistics\n\n"
        summary += f"- **Total Vulnerabilities:** {len(self.vulnerabilities)}\n"
        summary += f"- **Critical Severity:** {critical_vulns}\n"
        summary += f"- **High Severity:** {high_vulns}\n"
        summary += f"- **Credentials Extracted:** {len(self.credentials)}\n"
        summary += f"- **Persistence Mechanisms:** {len(self.persistence)}\n"
        summary += f"- **Lateral Movement Attempts:** {len(self.lateral_movement)}\n\n"

        return summary

    def _generate_vulnerabilities_section(self) -> str:
        """Generate vulnerabilities section."""
        if not self.vulnerabilities:
            return ""

        section = "## Identified Vulnerabilities\n\n"
        section += "| CVE ID | Name | Severity | Status |\n"
        section += "|--------|------|----------|--------|\n"

        for vuln in sorted(self.vulnerabilities, key=lambda x: x["severity"], reverse=True):
            section += f"| {vuln['cve_id']} | {vuln['name']} | {vuln['severity'].upper()} | {vuln['status']} |\n"

        section += "\n### Vulnerability Details\n\n"

        for vuln in self.vulnerabilities:
            section += f"#### {vuln['cve_id']}: {vuln['name']}\n\n"
            section += f"**Severity:** {vuln['severity'].upper()}\n\n"
            section += f"**Status:** {vuln['status']}\n\n"

            if vuln.get("details"):
                section += "**Details:**\n\n"
                for key, value in vuln["details"].items():
                    section += f"- **{key}:** {value}\n"
                section += "\n"

        return section

    def _generate_credentials_section(self) -> str:
        """Generate credentials section."""
        if not self.credentials:
            return ""

        section = "## Extracted Credentials\n\n"
        section += "| Type | Source | Username |\n"
        section += "|------|--------|----------|\n"

        for cred in self.credentials:
            username = cred.get("username", "N/A")
            section += f"| {cred['type']} | {cred['source']} | {username} |\n"

        section += "\n"
        return section

    def _generate_persistence_section(self) -> str:
        """Generate persistence section."""
        if not self.persistence:
            return ""

        section = "## Persistence Mechanisms\n\n"

        for p in self.persistence:
            section += f"### {p['method']}\n\n"
            section += f"**Status:** {p['status']}\n\n"

            if p.get("details"):
                section += "**Details:**\n\n"
                for key, value in p["details"].items():
                    section += f"- **{key}:** {value}\n"
                section += "\n"

        return section

    def _generate_lateral_movement_section(self) -> str:
        """Generate lateral movement section."""
        if not self.lateral_movement:
            return ""

        section = "## Lateral Movement\n\n"
        section += "| Target | Method | Status |\n"
        section += "|--------|--------|--------|\n"

        for lm in self.lateral_movement:
            section += f"| {lm['target']} | {lm['method']} | {lm['status']} |\n"

        section += "\n"
        return section

    def _generate_findings_section(self) -> str:
        """Generate findings section."""
        if not self.findings:
            return ""

        section = "## Additional Findings\n\n"

        for finding in sorted(self.findings, key=lambda x: x["severity"], reverse=True):
            section += f"### {finding['title']}\n\n"
            section += f"**Category:** {finding['category']}\n\n"
            section += f"**Severity:** {finding['severity'].upper()}\n\n"
            section += f"**Description:** {finding['description']}\n\n"

            if finding.get("details"):
                section += "**Details:**\n\n"
                for key, value in finding["details"].items():
                    section += f"- **{key}:** {value}\n"
                section += "\n"

        return section

    def _generate_recommendations_section(self) -> str:
        """Generate recommendations section."""
        section = "## Recommendations\n\n"

        recommendations = []

        if self.vulnerabilities:
            recommendations.append("Update Jenkins to the latest version to patch identified vulnerabilities")

        if any(v.get("severity") == "critical" for v in self.vulnerabilities):
            recommendations.append("Immediately patch critical vulnerabilities")

        if self.credentials:
            recommendations.append("Rotate all exposed credentials immediately")
            recommendations.append("Implement secrets management solution")

        if self.persistence:
            recommendations.append("Audit system for unauthorized persistence mechanisms")

        if self.lateral_movement:
            recommendations.append("Implement network segmentation")

        recommendations.extend([
            "Enable audit logging and monitoring",
            "Implement principle of least privilege",
            "Regular security assessments",
            "Deploy security hardening configurations"
        ])

        for i, rec in enumerate(recommendations, 1):
            section += f"{i}. {rec}\n"

        section += "\n"
        return section

    def generate(
        self,
        target: str,
        jenkins_version: Optional[str] = None
    ) -> str:
        """Generate Markdown report.

        Args:
            target: Target Jenkins URL
            jenkins_version: Jenkins version

        Returns:
            Markdown report string
        """
        report = "# Jenkins Security Assessment Report\n\n"
        report += self._generate_executive_summary(target, jenkins_version)
        report += self._generate_vulnerabilities_section()
        report += self._generate_credentials_section()
        report += self._generate_persistence_section()
        report += self._generate_lateral_movement_section()
        report += self._generate_findings_section()
        report += self._generate_recommendations_section()

        report += "---\n\n"
        report += f"*Report generated by JenkinsBreaker on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*\n"

        return report

    def save(
        self,
        filename: str,
        target: str,
        jenkins_version: Optional[str] = None
    ) -> None:
        """Save Markdown report to file.

        Args:
            filename: Output filename
            target: Target Jenkins URL
            jenkins_version: Jenkins version
        """
        report_md = self.generate(target, jenkins_version)

        with open(filename, 'w') as f:
            f.write(report_md)


def create_markdown_report(
    target: str,
    findings: Optional[list[dict[str, Any]]] = None,
    credentials: Optional[list[dict[str, Any]]] = None,
    vulnerabilities: Optional[list[dict[str, Any]]] = None,
    jenkins_version: Optional[str] = None
) -> str:
    """Factory function to create Markdown report.

    Args:
        target: Target Jenkins URL
        findings: Optional list of findings
        credentials: Optional list of credentials
        vulnerabilities: Optional list of vulnerabilities
        jenkins_version: Optional Jenkins version

    Returns:
        Markdown report string
    """
    reporter = MarkdownReporter()

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
