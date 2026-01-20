"""
YAML configuration management for JenkinsBreaker.

Supports:
- Target configuration
- Exploit parameters
- Payload settings
- Exploit chains
- Environment variable overrides
"""

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class TargetConfig:
    """Target Jenkins instance configuration."""

    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    proxy: Optional[str] = None
    delay: float = 0.0
    verify_ssl: bool = False
    timeout: int = 10
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetConfig":
        """Create from dictionary with environment variable expansion."""
        expanded = {
            key: cls._expand_env(value) if isinstance(value, str) else value
            for key, value in data.items()
        }
        return cls(**{k: v for k, v in expanded.items() if k in cls.__dataclass_fields__})

    @staticmethod
    def _expand_env(value: str) -> str:
        """Expand environment variables in string."""
        if value.startswith('${') and value.endswith('}'):
            env_var = value[2:-1]
            return os.getenv(env_var, value)
        return value


@dataclass
class ExploitConfig:
    """Exploit execution configuration."""

    cve_id: str
    enabled: bool = True
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExploitConfig":
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class PayloadConfig:
    """Payload generation configuration."""

    type: str = "reverse_shell"
    lhost: Optional[str] = None
    lport: Optional[int] = None
    lang: str = "bash"
    obfuscate: bool = False
    msfvenom_path: str = "msfvenom"
    msfvenom_type: str = "windows/meterpreter/reverse_tcp"
    custom_payload: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PayloadConfig":
        """Create from dictionary with environment variable expansion."""
        expanded = {}
        for key, value in data.items():
            if isinstance(value, str):
                expanded[key] = TargetConfig._expand_env(value)
            else:
                expanded[key] = value
        return cls(**{k: v for k, v in expanded.items() if k in cls.__dataclass_fields__})


@dataclass
class ChainConfig:
    """Exploit chain configuration."""

    name: str
    description: str = ""
    exploits: list[str] = field(default_factory=list)
    stop_on_failure: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChainConfig":
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ReportConfig:
    """Reporting configuration."""

    output_dir: str = "reports"
    formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    include_screenshots: bool = False
    redact_secrets: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportConfig":
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Config:
    """Complete JenkinsBreaker configuration."""

    target: TargetConfig
    exploits: list[ExploitConfig] = field(default_factory=list)
    payloads: PayloadConfig = field(default_factory=PayloadConfig)
    chains: list[ChainConfig] = field(default_factory=list)
    reporting: ReportConfig = field(default_factory=ReportConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        """Create from dictionary."""
        target = TargetConfig.from_dict(data.get('target', {}))

        exploits = [
            ExploitConfig.from_dict(e)
            for e in data.get('exploits', [])
        ]

        payloads = PayloadConfig.from_dict(data.get('payloads', {}))

        chains = [
            ChainConfig.from_dict(c)
            for c in data.get('chains', [])
        ]

        reporting = ReportConfig.from_dict(data.get('reporting', {}))

        return cls(
            target=target,
            exploits=exploits,
            payloads=payloads,
            chains=chains,
            reporting=reporting
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class ConfigLoader:
    """
    Loads and validates JenkinsBreaker configuration from YAML files.

    Example:
        loader = ConfigLoader()
        config = loader.load("config/targets.yaml")

        # Or with environment overrides
        config = loader.load_with_overrides(
            "config/targets.yaml",
            target_url="http://localhost:8080"
        )
    """

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        """
        Initialize config loader.

        Args:
            config_dir: Base directory for config files
        """
        self.config_dir = config_dir or Path("config")

    def load(self, path: str) -> Config:
        """
        Load configuration from YAML file.

        Args:
            path: Path to YAML file (relative to config_dir if not absolute)

        Returns:
            Config object

        Raises:
            FileNotFoundError: If config file not found
            ValueError: If config is invalid
        """
        config_path = Path(path)

        if not config_path.is_absolute():
            config_path = self.config_dir / config_path

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path) as f:
            data = yaml.safe_load(f)

        if not data:
            raise ValueError(f"Empty or invalid config file: {config_path}")

        return Config.from_dict(data)

    def load_with_overrides(
        self,
        path: str,
        **overrides: Any
    ) -> Config:
        """
        Load configuration with command-line overrides.

        Args:
            path: Path to YAML file
            **overrides: Override values (e.g., target_url="http://...")

        Returns:
            Config object with overrides applied
        """
        config = self.load(path)

        for key, value in overrides.items():
            if key.startswith('target_'):
                attr = key[7:]
                if hasattr(config.target, attr):
                    setattr(config.target, attr, value)

            elif key.startswith('payloads_'):
                attr = key[9:]
                if hasattr(config.payloads, attr):
                    setattr(config.payloads, attr, value)

            elif key.startswith('reporting_'):
                attr = key[10:]
                if hasattr(config.reporting, attr):
                    setattr(config.reporting, attr, value)

        return config

    def save(self, config: Config, path: str) -> None:
        """
        Save configuration to YAML file.

        Args:
            config: Config object
            path: Output path
        """
        config_path = Path(path)

        if not config_path.is_absolute():
            config_path = self.config_dir / config_path

        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, 'w') as f:
            yaml.dump(config.to_dict(), f, default_flow_style=False, sort_keys=False)

    @staticmethod
    def create_example(output_path: str) -> None:
        """
        Create example configuration file.

        Args:
            output_path: Path to write example config
        """
        example = {
            'target': {
                'url': 'http://localhost:8080',
                'username': 'admin',
                'password': 'admin',
                'delay': 0.0,
                'verify_ssl': False,
                'timeout': 10
            },
            'exploits': [
                {
                    'cve_id': 'CVE-2024-23897',
                    'enabled': True,
                    'params': {
                        'file_path': '/etc/passwd'
                    }
                }
            ],
            'payloads': {
                'type': 'reverse_shell',
                'lhost': '${LHOST}',
                'lport': 4444,
                'lang': 'bash',
                'obfuscate': False
            },
            'chains': [
                {
                    'name': 'full_compromise',
                    'description': 'File read -> RCE -> credential dump',
                    'exploits': [
                        'CVE-2024-23897',
                        'CVE-2019-1003029'
                    ],
                    'stop_on_failure': True
                }
            ],
            'reporting': {
                'output_dir': 'reports',
                'formats': ['json', 'markdown', 'html'],
                'include_screenshots': False,
                'redact_secrets': True
            }
        }

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with open(output, 'w') as f:
            yaml.dump(example, f, default_flow_style=False, sort_keys=False)
