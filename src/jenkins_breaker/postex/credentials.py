"""Credential extraction and secret hunting module.

Extracts credentials from various sources including AWS, Azure, GCP,
SSH keys, Docker, NPM, Maven, and database configurations.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class Credential:
    """Represents an extracted credential."""
    type: str
    username: Optional[str] = None
    password: Optional[str] = None
    key: Optional[str] = None
    token: Optional[str] = None
    source: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class CredentialExtractor:
    """Extracts credentials from various sources."""

    def __init__(self):
        """Initialize credential extractor."""
        self.credentials: list[Credential] = []
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, re.Pattern]:
        """Compile regex patterns for credential detection.

        Returns:
            Dictionary of compiled regex patterns
        """
        return {
            "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "aws_secret": re.compile(r'aws_secret_access_key\s*=\s*([^\s]+)'),
            "azure_tenant": re.compile(r'tenant[_-]?id[\'"]?\s*[:=]\s*[\'"]?([a-f0-9-]{36})', re.IGNORECASE),
            "azure_client": re.compile(r'client[_-]?id[\'"]?\s*[:=]\s*[\'"]?([a-f0-9-]{36})', re.IGNORECASE),
            "azure_secret": re.compile(r'client[_-]?secret[\'"]?\s*[:=]\s*[\'"]?([^\s\'"]+)', re.IGNORECASE),
            "gcp_key": re.compile(r'"type":\s*"service_account"'),
            "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
            "slack_token": re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'),
            "jwt": re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            "api_key": re.compile(r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{20,})', re.IGNORECASE),
            "password": re.compile(r'password[\'"]?\s*[:=]\s*[\'"]?([^\s\'"]+)', re.IGNORECASE),
            "private_key": re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
        }

    def extract_from_file(self, file_path: str) -> list[Credential]:
        """Extract credentials from file content.

        Args:
            file_path: Path to file to scan

        Returns:
            List of extracted credentials
        """
        try:
            with open(file_path, encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return self.extract_from_content(content, source=file_path)
        except OSError:
            return []

    def extract_from_content(self, content: str, source: Optional[str] = None) -> list[Credential]:
        """Extract credentials from text content.

        Args:
            content: Content to scan
            source: Optional source identifier

        Returns:
            List of extracted credentials
        """
        found_credentials = []

        if self.patterns["aws_key"].search(content):
            for match in self.patterns["aws_key"].finditer(content):
                found_credentials.append(Credential(
                    type="aws_access_key",
                    key=match.group(0),
                    source=source
                ))

        secret_match = self.patterns["aws_secret"].search(content)
        if secret_match:
            found_credentials.append(Credential(
                type="aws_secret_key",
                key=secret_match.group(1),
                source=source
            ))

        tenant_match = self.patterns["azure_tenant"].search(content)
        client_match = self.patterns["azure_client"].search(content)
        secret_match = self.patterns["azure_secret"].search(content)

        if tenant_match or client_match or secret_match:
            found_credentials.append(Credential(
                type="azure_service_principal",
                metadata={
                    "tenant_id": tenant_match.group(1) if tenant_match else None,
                    "client_id": client_match.group(1) if client_match else None,
                    "client_secret": secret_match.group(1) if secret_match else None,
                },
                source=source
            ))

        if self.patterns["gcp_key"].search(content):
            found_credentials.append(Credential(
                type="gcp_service_account",
                key=content,
                source=source
            ))

        for match in self.patterns["github_token"].finditer(content):
            found_credentials.append(Credential(
                type="github_token",
                token=match.group(0),
                source=source
            ))

        for match in self.patterns["slack_token"].finditer(content):
            found_credentials.append(Credential(
                type="slack_token",
                token=match.group(0),
                source=source
            ))

        for match in self.patterns["jwt"].finditer(content):
            found_credentials.append(Credential(
                type="jwt",
                token=match.group(0),
                source=source
            ))

        api_match = self.patterns["api_key"].search(content)
        if api_match:
            found_credentials.append(Credential(
                type="api_key",
                key=api_match.group(1),
                source=source
            ))

        if self.patterns["private_key"].search(content):
            found_credentials.append(Credential(
                type="ssh_private_key",
                key=content,
                source=source
            ))

        return found_credentials

    def scan_aws_credentials(self, base_path: str = "~") -> list[Credential]:
        """Scan for AWS credentials.

        Args:
            base_path: Base directory to search from

        Returns:
            List of AWS credentials
        """
        credentials = []
        aws_creds_path = Path(base_path).expanduser() / ".aws" / "credentials"
        aws_config_path = Path(base_path).expanduser() / ".aws" / "config"

        for path in [aws_creds_path, aws_config_path]:
            if path.exists():
                credentials.extend(self.extract_from_file(str(path)))

        for env_var in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]:
            value = os.environ.get(env_var)
            if value:
                credentials.append(Credential(
                    type=f"aws_env_{env_var.lower()}",
                    key=value,
                    source=f"environment:{env_var}"
                ))

        return credentials

    def scan_azure_credentials(self, base_path: str = "~") -> list[Credential]:
        """Scan for Azure credentials.

        Args:
            base_path: Base directory to search from

        Returns:
            List of Azure credentials
        """
        credentials = []
        azure_path = Path(base_path).expanduser() / ".azure"

        if azure_path.exists():
            for file_path in azure_path.rglob("*"):
                if file_path.is_file():
                    credentials.extend(self.extract_from_file(str(file_path)))

        for env_var in ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"]:
            value = os.environ.get(env_var)
            if value:
                credentials.append(Credential(
                    type=f"azure_env_{env_var.lower()}",
                    key=value,
                    source=f"environment:{env_var}"
                ))

        return credentials

    def scan_gcp_credentials(self, base_path: str = "~") -> list[Credential]:
        """Scan for GCP credentials.

        Args:
            base_path: Base directory to search from

        Returns:
            List of GCP credentials
        """
        credentials = []
        gcp_path = Path(base_path).expanduser() / ".config" / "gcloud"

        if gcp_path.exists():
            for file_path in gcp_path.rglob("*.json"):
                credentials.extend(self.extract_from_file(str(file_path)))

        gcp_env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if gcp_env and Path(gcp_env).exists():
            credentials.extend(self.extract_from_file(gcp_env))

        return credentials

    def scan_ssh_keys(self, base_path: str = "~") -> list[Credential]:
        """Scan for SSH private keys.

        Args:
            base_path: Base directory to search from

        Returns:
            List of SSH private keys
        """
        credentials = []
        ssh_path = Path(base_path).expanduser() / ".ssh"

        if ssh_path.exists():
            key_files = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
            for key_file in key_files:
                key_path = ssh_path / key_file
                if key_path.exists():
                    try:
                        with open(key_path) as f:
                            key_content = f.read()
                            credentials.append(Credential(
                                type="ssh_private_key",
                                key=key_content,
                                source=str(key_path),
                                metadata={"key_type": key_file}
                            ))
                    except OSError:
                        pass

        return credentials

    def scan_docker_credentials(self, base_path: str = "~") -> list[Credential]:
        """Scan for Docker registry credentials.

        Args:
            base_path: Base directory to search from

        Returns:
            List of Docker credentials
        """
        credentials = []
        docker_config = Path(base_path).expanduser() / ".docker" / "config.json"

        if docker_config.exists():
            credentials.extend(self.extract_from_file(str(docker_config)))

        return credentials

    def scan_npm_credentials(self, base_path: str = "~") -> list[Credential]:
        """Scan for NPM credentials.

        Args:
            base_path: Base directory to search from

        Returns:
            List of NPM credentials
        """
        credentials = []
        npmrc_path = Path(base_path).expanduser() / ".npmrc"

        if npmrc_path.exists():
            credentials.extend(self.extract_from_file(str(npmrc_path)))

        return credentials

    def scan_maven_credentials(self, base_path: str = "~") -> list[Credential]:
        """Scan for Maven credentials.

        Args:
            base_path: Base directory to search from

        Returns:
            List of Maven credentials
        """
        credentials = []
        maven_settings = Path(base_path).expanduser() / ".m2" / "settings.xml"

        if maven_settings.exists():
            credentials.extend(self.extract_from_file(str(maven_settings)))

        return credentials

    def scan_database_credentials(self, base_path: str = "~") -> list[Credential]:
        """Scan for database credentials.

        Args:
            base_path: Base directory to search from

        Returns:
            List of database credentials
        """
        credentials = []
        db_files = [".pgpass", ".my.cnf", ".mysql_history"]

        for db_file in db_files:
            db_path = Path(base_path).expanduser() / db_file
            if db_path.exists():
                credentials.extend(self.extract_from_file(str(db_path)))

        return credentials

    def scan_all(self, base_path: str = "~") -> dict[str, list[Credential]]:
        """Scan all credential sources.

        Args:
            base_path: Base directory to search from

        Returns:
            Dictionary mapping credential types to lists of credentials
        """
        return {
            "aws": self.scan_aws_credentials(base_path),
            "azure": self.scan_azure_credentials(base_path),
            "gcp": self.scan_gcp_credentials(base_path),
            "ssh": self.scan_ssh_keys(base_path),
            "docker": self.scan_docker_credentials(base_path),
            "npm": self.scan_npm_credentials(base_path),
            "maven": self.scan_maven_credentials(base_path),
            "database": self.scan_database_credentials(base_path),
        }


def extract_credentials(base_path: str = "~") -> dict[str, list[Credential]]:
    """Factory function to extract all credentials.

    Args:
        base_path: Base directory to search from

    Returns:
        Dictionary of extracted credentials by type
    """
    extractor = CredentialExtractor()
    return extractor.scan_all(base_path)
