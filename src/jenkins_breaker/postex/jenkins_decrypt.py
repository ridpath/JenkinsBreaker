"""Jenkins credential decryption module.

Decrypts Jenkins secrets using master.key and hudson.util.Secret files.
Supports both old (AES-ECB) and new (AES-CBC) encryption formats.
"""

import base64
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

from Crypto.Cipher import AES

DECRYPTION_MAGIC = b'::::MAGIC::::'


@dataclass
class DecryptedSecret:
    """Represents a decrypted Jenkins secret."""
    encrypted_value: str
    decrypted_value: str
    source: Optional[str] = None
    tag_name: Optional[str] = None


class JenkinsDecryptor:
    """Decrypt Jenkins secrets using master.key and hudson.util.Secret."""

    def __init__(self, master_key: Optional[str] = None, hudson_secret: Optional[bytes] = None,
                 master_key_file: Optional[str] = None, hudson_secret_file: Optional[str] = None):
        """Initialize Jenkins decryptor.

        Args:
            master_key: Master key content as string
            hudson_secret: Hudson secret content as bytes
            master_key_file: Path to master.key file
            hudson_secret_file: Path to hudson.util.Secret file
        """
        self.master_key = master_key
        self.hudson_secret = hudson_secret
        self.master_key_file = master_key_file
        self.hudson_secret_file = hudson_secret_file
        self.confidentiality_key: Optional[bytes] = None

    def get_confidentiality_key(self) -> bytes:
        """Decrypt hudson.util.Secret to obtain confidentiality key.

        Returns:
            Confidentiality key bytes

        Raises:
            Exception: If master key or hudson secret not provided or decryption fails
        """
        if self.confidentiality_key:
            return self.confidentiality_key

        if self.master_key is None and self.master_key_file is None:
            raise Exception("Master key not provided - need either master_key or master_key_file")
        if self.hudson_secret is None and self.hudson_secret_file is None:
            raise Exception("Hudson secret not provided - need either hudson_secret or hudson_secret_file")

        if self.master_key is None:
            with open(self.master_key_file) as f:
                master_key = f.read().strip()
        else:
            master_key = self.master_key

        if self.hudson_secret is None:
            with open(self.hudson_secret_file, 'rb') as f:
                hudson_secret = f.read()
        else:
            hudson_secret = self.hudson_secret

        master_key_bytes = master_key.encode('utf-8')
        derived_key = sha256(master_key_bytes).digest()[:16]
        cipher = AES.new(derived_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(hudson_secret)

        if DECRYPTION_MAGIC not in decrypted:
            raise Exception("Confidentiality key decrypt failed (MAGIC marker missing)")

        self.confidentiality_key = decrypted[:16]
        return self.confidentiality_key

    def decrypt_secret_old(self, encrypted: bytes, key: bytes) -> Optional[str]:
        """Decrypt secrets using old Jenkins format (AES-ECB).

        Args:
            encrypted: Encrypted secret bytes
            key: Confidentiality key

        Returns:
            Decrypted secret string or None if failed
        """
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)

        if DECRYPTION_MAGIC not in decrypted:
            return None

        secret = decrypted.split(DECRYPTION_MAGIC)[0]

        try:
            decoded = secret.rstrip(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f").decode()
            return decoded
        except Exception:
            return None

    def decrypt_secret_new(self, encrypted: bytes, key: bytes) -> Optional[str]:
        """Decrypt secrets using new Jenkins format (AES-CBC).

        Args:
            encrypted: Encrypted secret bytes
            key: Confidentiality key

        Returns:
            Decrypted secret string or None if failed
        """
        iv = encrypted[9:25]
        payload = encrypted[25:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(payload)

        padding = decrypted[-1]
        if 1 <= padding <= 16:
            decrypted = decrypted[:-padding]

        try:
            return decrypted.decode(errors='ignore')
        except Exception:
            return None

    def decrypt_secret(self, b64_secret: str) -> Optional[str]:
        """Decrypt a base64-encoded Jenkins secret.

        Args:
            b64_secret: Base64-encoded encrypted secret

        Returns:
            Decrypted secret string or None if failed
        """
        if not self.confidentiality_key:
            self.confidentiality_key = self.get_confidentiality_key()

        try:
            encrypted = base64.b64decode(b64_secret)
        except Exception:
            return None

        if encrypted[0] == 1:
            return self.decrypt_secret_new(encrypted, self.confidentiality_key)
        else:
            return self.decrypt_secret_old(encrypted, self.confidentiality_key)

    def decrypt_credentials_file(self, xml_path: str) -> list[DecryptedSecret]:
        """Decrypt secrets from a Jenkins credentials XML file.

        Args:
            xml_path: Path to credentials.xml file

        Returns:
            List of DecryptedSecret objects
        """
        with open(xml_path, encoding='utf-8', errors='ignore') as f:
            content = f.read()

        tags = ['apiToken', 'password', 'privateKey', 'passphrase', 'secret', 'secretId', 'value', 'defaultValue']
        secrets_found = []

        for tag in tags:
            pattern = f"{tag}>\\{{?([A-Za-z0-9+/=]+)\\}}?</{tag}"
            matches = re.findall(pattern, content)
            for encrypted_value in matches:
                try:
                    decrypted = self.decrypt_secret(encrypted_value)
                    if decrypted:
                        secrets_found.append(DecryptedSecret(
                            encrypted_value=encrypted_value,
                            decrypted_value=decrypted,
                            source=xml_path,
                            tag_name=tag
                        ))
                except Exception:
                    pass

        return secrets_found

    def decrypt_from_content(self, content: str) -> list[DecryptedSecret]:
        """Decrypt secrets from raw content (any text/XML).

        Args:
            content: Content to scan for encrypted secrets

        Returns:
            List of DecryptedSecret objects
        """
        tags = ['apiToken', 'password', 'privateKey', 'passphrase', 'secret', 'secretId', 'value', 'defaultValue']
        secrets_found = []

        for tag in tags:
            pattern = f"{tag}>\\{{?([A-Za-z0-9+/=]+)\\}}?</{tag}"
            matches = re.findall(pattern, content)
            for encrypted_value in matches:
                try:
                    decrypted = self.decrypt_secret(encrypted_value)
                    if decrypted:
                        secrets_found.append(DecryptedSecret(
                            encrypted_value=encrypted_value,
                            decrypted_value=decrypted,
                            tag_name=tag
                        ))
                except Exception:
                    pass

        pattern = r'>{{?([A-Za-z0-9+/=]{20,})}}?</'
        matches = re.findall(pattern, content)
        for encrypted_value in matches:
            if any(s.encrypted_value == encrypted_value for s in secrets_found):
                continue
            try:
                decrypted = self.decrypt_secret(encrypted_value)
                if decrypted:
                    secrets_found.append(DecryptedSecret(
                        encrypted_value=encrypted_value,
                        decrypted_value=decrypted
                    ))
            except Exception:
                pass

        return secrets_found


def decrypt_jenkins_secret(encrypted_secret: str, master_key_file: str, hudson_secret_file: str) -> Optional[str]:
    """Factory function to decrypt a single Jenkins secret.

    Args:
        encrypted_secret: Base64-encoded encrypted secret
        master_key_file: Path to master.key
        hudson_secret_file: Path to hudson.util.Secret

    Returns:
        Decrypted secret or None if failed
    """
    decryptor = JenkinsDecryptor(
        master_key_file=master_key_file,
        hudson_secret_file=hudson_secret_file
    )
    return decryptor.decrypt_secret(encrypted_secret)


def decrypt_credentials_file(xml_path: str, master_key_file: str, hudson_secret_file: str) -> list[DecryptedSecret]:
    """Factory function to decrypt all secrets from credentials.xml.

    Args:
        xml_path: Path to credentials.xml
        master_key_file: Path to master.key
        hudson_secret_file: Path to hudson.util.Secret

    Returns:
        List of DecryptedSecret objects
    """
    decryptor = JenkinsDecryptor(
        master_key_file=master_key_file,
        hudson_secret_file=hudson_secret_file
    )
    return decryptor.decrypt_credentials_file(xml_path)
