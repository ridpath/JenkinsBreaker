"""
Authentication and TLS system for securing the WebUI.
Provides token-based authentication and automatic TLS certificate generation.
"""

import datetime as dt
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class TokenManager:
    """
    Manages authentication tokens for WebUI access.
    """

    def __init__(self, secret_key: Optional[str] = None):
        if secret_key is None:
            secret_key = secrets.token_hex(32)

        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.tokens: dict[str, dict] = {}

    def generate_token(
        self,
        username: str,
        expiry_hours: int = 24
    ) -> str:
        """
        Generate a secure authentication token.

        Args:
            username: Username for the token
            expiry_hours: Token validity in hours

        Returns:
            Authentication token
        """
        token = secrets.token_urlsafe(32)

        self.tokens[token] = {
            'username': username,
            'created': datetime.now().isoformat(),
            'expires': (datetime.now() + timedelta(hours=expiry_hours)).isoformat()
        }

        return token

    def validate_token(self, token: str) -> bool:
        """
        Validate an authentication token.

        Args:
            token: Token to validate

        Returns:
            True if valid, False otherwise
        """
        if token not in self.tokens:
            return False

        token_data = self.tokens[token]
        expires = datetime.fromisoformat(token_data['expires'])

        if datetime.now() > expires:
            del self.tokens[token]
            return False

        return True

    def get_token_user(self, token: str) -> Optional[str]:
        """Get username associated with a token."""
        if token in self.tokens:
            return self.tokens[token]['username']
        return None

    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False

    def cleanup_expired(self):
        """Remove expired tokens."""
        now = datetime.now()
        expired = []

        for token, data in self.tokens.items():
            expires = datetime.fromisoformat(data['expires'])
            if now > expires:
                expired.append(token)

        for token in expired:
            del self.tokens[token]


class UserManager:
    """
    Manages user authentication and authorization.
    """

    def __init__(self, users_file: Optional[Path] = None):
        if users_file is None:
            users_file = Path.cwd() / 'config' / 'users.json'

        self.users_file = Path(users_file)
        self.users: dict[str, dict] = {}

        self._load_users()

    def _load_users(self):
        """Load users from file."""
        if self.users_file.exists():
            try:
                with open(self.users_file) as f:
                    self.users = json.load(f)
            except Exception:
                pass

        if not self.users:
            self._create_default_user()

    def _save_users(self):
        """Save users to file."""
        self.users_file.parent.mkdir(exist_ok=True)
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)

    def _create_default_user(self):
        """Create default admin user."""
        self.users = {
            'admin': {
                'password_hash': self._hash_password('admin'),
                'role': 'admin',
                'created': datetime.now().isoformat()
            }
        }
        self._save_users()

    def _hash_password(self, password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate a user.

        Args:
            username: Username
            password: Password

        Returns:
            True if authenticated, False otherwise
        """
        if username not in self.users:
            return False

        password_hash = self._hash_password(password)
        return self.users[username]['password_hash'] == password_hash

    def add_user(
        self,
        username: str,
        password: str,
        role: str = 'operator'
    ) -> bool:
        """
        Add a new user.

        Args:
            username: Username
            password: Password
            role: User role (admin, operator, readonly)

        Returns:
            True if added, False if user exists
        """
        if username in self.users:
            return False

        self.users[username] = {
            'password_hash': self._hash_password(password),
            'role': role,
            'created': datetime.now().isoformat()
        }

        self._save_users()
        return True

    def change_password(
        self,
        username: str,
        old_password: str,
        new_password: str
    ) -> bool:
        """
        Change user password.

        Args:
            username: Username
            old_password: Current password
            new_password: New password

        Returns:
            True if changed, False if authentication failed
        """
        if not self.authenticate(username, old_password):
            return False

        self.users[username]['password_hash'] = self._hash_password(new_password)
        self._save_users()
        return True

    def delete_user(self, username: str) -> bool:
        """Delete a user."""
        if username == 'admin':
            return False

        if username in self.users:
            del self.users[username]
            self._save_users()
            return True

        return False

    def get_user_role(self, username: str) -> Optional[str]:
        """Get user role."""
        if username in self.users:
            return self.users[username]['role']
        return None


class TLSCertificateGenerator:
    """
    Generates self-signed TLS certificates for secure WebUI access.
    """

    @staticmethod
    def generate_self_signed_cert(
        cert_file: Path,
        key_file: Path,
        hostname: str = "localhost",
        validity_days: int = 365
    ):
        """
        Generate a self-signed TLS certificate.

        Args:
            cert_file: Path to save certificate
            key_file: Path to save private key
            hostname: Hostname for the certificate
            validity_days: Certificate validity in days
        """
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "JenkinsBreaker"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            dt.datetime.utcnow()
        ).not_valid_after(
            dt.datetime.utcnow() + dt.timedelta(days=validity_days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

        cert_file.parent.mkdir(exist_ok=True)
        key_file.parent.mkdir(exist_ok=True)

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        key_file.chmod(0o600)


class SecurityManager:
    """
    High-level security management for the WebUI.
    """

    def __init__(
        self,
        users_file: Optional[Path] = None,
        cert_dir: Optional[Path] = None
    ):
        self.user_manager = UserManager(users_file)
        self.token_manager = TokenManager()

        if cert_dir is None:
            cert_dir = Path.cwd() / 'config' / 'certs'

        self.cert_dir = Path(cert_dir)
        self.cert_file = self.cert_dir / 'server.crt'
        self.key_file = self.cert_dir / 'server.key'

    def ensure_tls_cert(self, hostname: str = "localhost"):
        """Ensure TLS certificate exists, generate if not."""
        if not self.cert_file.exists() or not self.key_file.exists():
            TLSCertificateGenerator.generate_self_signed_cert(
                self.cert_file,
                self.key_file,
                hostname=hostname
            )

    def login(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate user and generate token.

        Args:
            username: Username
            password: Password

        Returns:
            Authentication token, or None if authentication failed
        """
        if self.user_manager.authenticate(username, password):
            return self.token_manager.generate_token(username)
        return None

    def validate_request(self, token: str) -> bool:
        """Validate a request token."""
        return self.token_manager.validate_token(token)

    def logout(self, token: str) -> bool:
        """Logout a user by revoking their token."""
        return self.token_manager.revoke_token(token)

    def get_tls_config(self) -> dict[str, Path]:
        """Get TLS configuration paths."""
        return {
            'certfile': self.cert_file,
            'keyfile': self.key_file
        }


# Import ipaddress for TLS certificate generation
import ipaddress
