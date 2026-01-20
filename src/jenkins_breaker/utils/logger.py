"""
Structured logging with Rich console output for JenkinsBreaker.
"""

import logging
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "critical": "bold white on red"
})


console = Console(theme=custom_theme)


class JenkinsLogger:
    """
    Structured logger with Rich console output.

    Features:
    - Multiple log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - Rich console formatting
    - File output support
    - Context-aware logging

    Example:
        logger = JenkinsLogger("jenkins-breaker")
        logger.info("Starting enumeration")
        logger.success("Exploit succeeded")
        logger.error("Connection failed", exc_info=True)
    """

    def __init__(
        self,
        name: str = "jenkins_breaker",
        level: int = logging.INFO,
        log_file: Optional[str] = None,
        console_output: bool = True
    ) -> None:
        """
        Initialize logger.

        Args:
            name: Logger name
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path for log output
            console_output: Enable console output
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        if console_output:
            console_handler = RichHandler(
                console=console,
                show_time=True,
                show_path=False,
                markup=True,
                rich_tracebacks=True,
                tracebacks_show_locals=False
            )
            console_handler.setLevel(level)
            self.logger.addHandler(console_handler)

        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)

            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)

            self.logger.addHandler(file_handler)

    def debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self.logger.debug(message, **kwargs)

    def info(self, message: str, **kwargs) -> None:
        """Log info message."""
        self.logger.info(message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self.logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        """Log error message."""
        self.logger.error(message, **kwargs)

    def critical(self, message: str, **kwargs) -> None:
        """Log critical message."""
        self.logger.critical(message, **kwargs)

    def success(self, message: str) -> None:
        """Log success message with special formatting."""
        console.print(f"[success][+][/success] {message}")
        self.logger.info(f"SUCCESS: {message}")

    def failure(self, message: str) -> None:
        """Log failure message with special formatting."""
        console.print(f"[error][-][/error] {message}")
        self.logger.warning(f"FAILURE: {message}")

    def exploit_start(self, cve_id: str, target: str) -> None:
        """Log exploit start."""
        console.print(f"[info][*][/info] Attempting {cve_id} against {target}")
        self.logger.info(f"Exploit started: {cve_id} -> {target}")

    def exploit_success(self, cve_id: str, details: str = "") -> None:
        """Log exploit success."""
        msg = f"Exploit {cve_id} succeeded"
        if details:
            msg += f": {details}"
        console.print(f"[success][+][/success] {msg}")
        self.logger.info(f"EXPLOIT_SUCCESS: {cve_id} - {details}")

    def exploit_failure(self, cve_id: str, reason: str = "") -> None:
        """Log exploit failure."""
        msg = f"Exploit {cve_id} failed"
        if reason:
            msg += f": {reason}"
        console.print(f"[error][-][/error] {msg}")
        self.logger.warning(f"EXPLOIT_FAILURE: {cve_id} - {reason}")

    def set_level(self, level: int) -> None:
        """
        Change log level.

        Args:
            level: New log level
        """
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)


_default_logger: Optional[JenkinsLogger] = None


def get_logger(
    name: str = "jenkins_breaker",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    console_output: bool = True
) -> JenkinsLogger:
    """
    Get or create default logger instance.

    Args:
        name: Logger name
        level: Log level
        log_file: Optional file path
        console_output: Enable console output

    Returns:
        JenkinsLogger instance
    """
    global _default_logger

    if _default_logger is None:
        _default_logger = JenkinsLogger(
            name=name,
            level=level,
            log_file=log_file,
            console_output=console_output
        )

    return _default_logger


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = "jenkinsbreaker.log",
    console_output: bool = True,
    debug_file: Optional[str] = "debug.log"
) -> JenkinsLogger:
    """
    Setup default logging configuration.

    Args:
        level: Log level
        log_file: Optional file path
        console_output: Enable console output
        debug_file: Optional debug log file path

    Returns:
        Configured JenkinsLogger instance
    """
    global _default_logger

    _default_logger = JenkinsLogger(
        name="jenkins_breaker",
        level=level,
        log_file=log_file,
        console_output=console_output
    )
    
    if debug_file:
        log_path = Path(debug_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        debug_handler = logging.FileHandler(debug_file, mode='a')
        debug_handler.setLevel(logging.DEBUG)
        
        debug_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        debug_handler.setFormatter(debug_formatter)
        
        _default_logger.logger.addHandler(debug_handler)

    return _default_logger
