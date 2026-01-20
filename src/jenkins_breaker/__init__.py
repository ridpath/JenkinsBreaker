"""
JenkinsBreaker: CI/CD Exploitation Framework

A modular framework for Jenkins infrastructure assessment and exploitation.
Designed for authorized security testing, CTF competitions, and research.
"""

__version__ = "2.0.0"
__author__ = "ridpath"
__license__ = "MIT"

from jenkins_breaker.core.authentication import AuthenticationValidator, CrumbManager
from jenkins_breaker.core.config import Config, ConfigLoader
from jenkins_breaker.core.enumeration import JenkinsEnumerator, JenkinsVersion
from jenkins_breaker.core.session import JenkinsSession, SessionConfig
from jenkins_breaker.modules.base import (
    ExploitMetadata,
    ExploitModule,
    ExploitResult,
    exploit_registry,
)
from jenkins_breaker.utils.logger import console, get_logger, setup_logging

__all__ = [
    "JenkinsSession",
    "SessionConfig",
    "CrumbManager",
    "AuthenticationValidator",
    "JenkinsEnumerator",
    "JenkinsVersion",
    "Config",
    "ConfigLoader",
    "ExploitModule",
    "ExploitMetadata",
    "ExploitResult",
    "exploit_registry",
    "setup_logging",
    "get_logger",
    "console",
    "__version__",
]
