"""
JenkinsBreaker UI modules - Complete C2-style interface system.
"""

from jenkins_breaker.ui.auth import TLSCertificateGenerator, TokenManager, UserManager
from jenkins_breaker.ui.console import JenkinsConsole
from jenkins_breaker.ui.loot import Artifact, Credential, LootManager
from jenkins_breaker.ui.macros import Macro, MacroCommand, MacroRecorder
from jenkins_breaker.ui.manager import AsyncJobExecutor, JobManager
from jenkins_breaker.ui.renderer import FormRenderer, render_exploit_form
from jenkins_breaker.ui.server import C2Server, create_server
from jenkins_breaker.ui.terminal import (
    TerminalManager,
    create_terminal_manager,
    generate_terminal_html,
)
from jenkins_breaker.ui.tui import JenkinsBreakerTUI
from jenkins_breaker.ui.tui import main as tui_main
from jenkins_breaker.ui.visualization import TopologyVisualizer, visualize_jenkins
from jenkins_breaker.ui.webui import app as webui_app
from jenkins_breaker.ui.webui import main as webui_main

__all__ = [
    "JenkinsBreakerTUI",
    "tui_main",
    "webui_app",
    "webui_main",
    "JenkinsConsole",
    "JobManager",
    "AsyncJobExecutor",
    "LootManager",
    "Credential",
    "Artifact",
    "MacroRecorder",
    "Macro",
    "MacroCommand",
    "TokenManager",
    "UserManager",
    "TLSCertificateGenerator",
    "C2Server",
    "create_server",
    "TopologyVisualizer",
    "visualize_jenkins",
    "FormRenderer",
    "render_exploit_form",
    "TerminalManager",
    "create_terminal_manager",
    "generate_terminal_html",
]
