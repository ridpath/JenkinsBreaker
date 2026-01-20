"""Base payload generation framework for JenkinsBreaker.

This module provides the foundation for generating various payload types
with encoding, obfuscation, and template rendering capabilities.
"""

import base64
import binascii
import random
import string
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class PayloadType(Enum):
    """Supported payload types."""
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    METERPRETER = "meterpreter"
    POWERSHELL = "powershell"
    CUSTOM = "custom"


class EncodingType(Enum):
    """Supported encoding types."""
    NONE = "none"
    BASE64 = "base64"
    HEX = "hex"
    URL = "url"
    UNICODE = "unicode"


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""
    payload_type: PayloadType
    target_os: str
    encoding: EncodingType = EncodingType.NONE
    obfuscate: bool = False
    template_vars: Optional[dict[str, Any]] = None


class PayloadEncoder:
    """Handles payload encoding and obfuscation."""

    @staticmethod
    def encode_base64(payload: str) -> str:
        """Encode payload in base64."""
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def encode_hex(payload: str) -> str:
        """Encode payload in hexadecimal."""
        return binascii.hexlify(payload.encode()).decode()

    @staticmethod
    def encode_url(payload: str) -> str:
        """URL encode payload."""
        from urllib.parse import quote
        return quote(payload)

    @staticmethod
    def encode_unicode(payload: str) -> str:
        """Unicode escape payload."""
        return payload.encode('unicode_escape').decode()

    @staticmethod
    def obfuscate_simple(payload: str, seed: Optional[int] = None) -> str:
        """Apply simple obfuscation to payload.

        Args:
            payload: The payload to obfuscate
            seed: Random seed for reproducible obfuscation

        Returns:
            Obfuscated payload string
        """
        if seed is not None:
            random.seed(seed)

        chars = list(payload)
        for i in range(len(chars)):
            if random.random() > 0.7 and chars[i].isspace():
                chars[i] = random.choice([' ', '\t', '\n'])

        return ''.join(chars)

    @staticmethod
    def obfuscate_string_concat(payload: str) -> str:
        """Obfuscate by breaking strings into concatenations."""
        if len(payload) < 10:
            return payload

        parts = []
        chunk_size = random.randint(3, 8)

        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i+chunk_size]
            parts.append(f'"{chunk}"')

        return ' + '.join(parts)


class PayloadTemplate:
    """Template rendering for payloads."""

    @staticmethod
    def render(template: str, variables: dict[str, Any]) -> str:
        """Render template with variables.

        Args:
            template: Template string with {{variable}} placeholders
            variables: Dictionary of variable names to values

        Returns:
            Rendered template string
        """
        result = template
        for key, value in variables.items():
            placeholder = f"{{{{{key}}}}}"
            result = result.replace(placeholder, str(value))
        return result

    @staticmethod
    def render_jinja(template: str, variables: dict[str, Any]) -> str:
        """Render Jinja2 template if available, fallback to simple render.

        Args:
            template: Jinja2 template string
            variables: Dictionary of template variables

        Returns:
            Rendered template string
        """
        try:
            from jinja2 import Template
            return Template(template).render(**variables)
        except ImportError:
            return PayloadTemplate.render(template, variables)


class PayloadGenerator:
    """Main payload generator class."""

    def __init__(self, config: PayloadConfig):
        """Initialize payload generator.

        Args:
            config: PayloadConfig instance with generation parameters
        """
        self.config = config
        self.encoder = PayloadEncoder()

    def generate(self, template: str, variables: Optional[dict[str, Any]] = None) -> str:
        """Generate payload from template.

        Args:
            template: Payload template string
            variables: Optional template variables (merged with config vars)

        Returns:
            Generated and encoded payload string
        """
        all_vars = self.config.template_vars or {}
        if variables:
            all_vars.update(variables)

        payload = PayloadTemplate.render(template, all_vars)

        if self.config.obfuscate:
            payload = self.encoder.obfuscate_simple(payload)

        if self.config.encoding == EncodingType.BASE64:
            payload = self.encoder.encode_base64(payload)
        elif self.config.encoding == EncodingType.HEX:
            payload = self.encoder.encode_hex(payload)
        elif self.config.encoding == EncodingType.URL:
            payload = self.encoder.encode_url(payload)
        elif self.config.encoding == EncodingType.UNICODE:
            payload = self.encoder.encode_unicode(payload)

        return payload

    def generate_random_string(self, length: int = 8, charset: str = "alphanumeric") -> str:
        """Generate random string for variable names, etc.

        Args:
            length: Length of random string
            charset: Character set to use (alphanumeric, alpha, numeric, hex)

        Returns:
            Random string
        """
        if charset == "alphanumeric":
            chars = string.ascii_letters + string.digits
        elif charset == "alpha":
            chars = string.ascii_letters
        elif charset == "numeric":
            chars = string.digits
        elif charset == "hex":
            chars = string.hexdigits.lower()
        else:
            chars = charset

        return ''.join(random.choice(chars) for _ in range(length))

    def wrap_encoder(self, payload: str, encoder_cmd: str) -> str:
        """Wrap payload with encoder command.

        Args:
            payload: The payload to wrap
            encoder_cmd: Command template for decoding (e.g., "echo {payload} | base64 -d | bash")

        Returns:
            Wrapped payload string
        """
        return encoder_cmd.format(payload=payload)


def create_generator(
    payload_type: PayloadType,
    target_os: str = "linux",
    encoding: EncodingType = EncodingType.NONE,
    obfuscate: bool = False,
    **kwargs: Any
) -> PayloadGenerator:
    """Factory function to create PayloadGenerator.

    Args:
        payload_type: Type of payload to generate
        target_os: Target operating system
        encoding: Encoding type to apply
        obfuscate: Whether to apply obfuscation
        **kwargs: Additional template variables

    Returns:
        Configured PayloadGenerator instance
    """
    config = PayloadConfig(
        payload_type=payload_type,
        target_os=target_os,
        encoding=encoding,
        obfuscate=obfuscate,
        template_vars=kwargs
    )
    return PayloadGenerator(config)
