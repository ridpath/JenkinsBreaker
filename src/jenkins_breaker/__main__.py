"""
JenkinsBreaker CLI entry point.
"""

import argparse
import logging
import sys

from jenkins_breaker.core.config import ConfigLoader
from jenkins_breaker.core.enumeration import JenkinsEnumerator
from jenkins_breaker.core.session import JenkinsSession, SessionConfig
from jenkins_breaker.modules.base import exploit_registry
from jenkins_breaker.utils.logger import console, setup_logging


def cmd_enumerate(args: argparse.Namespace) -> int:
    """Execute enumeration command."""
    logger = setup_logging(
        level=logging.DEBUG if args.verbose else logging.INFO,
        log_file=args.log_file,
        console_output=not args.quiet
    )

    try:
        config = SessionConfig(
            url=args.url,
            username=args.username,
            password=args.password,
            proxy=args.proxy,
            delay=args.delay,
            timeout=args.timeout
        )

        session = JenkinsSession(config)

        if not session.connect():
            logger.error(f"Failed to connect to {args.url}")
            return 1

        logger.success(f"Connected to Jenkins at {args.url}")

        enumerator = JenkinsEnumerator(
            base_url=config.url,
            auth=session.auth,
            proxies=session.config.proxies if session.config.proxy else {},
            verify_ssl=config.verify_ssl,
            timeout=config.timeout,
            delay=config.delay
        )

        logger.info("Starting enumeration")
        result = enumerator.enumerate_all()

        if result.version:
            console.print(f"\n[bold cyan]Version:[/bold cyan] {result.version.version} (detected via {result.version.source})")

        if result.plugins:
            console.print(f"\n[bold cyan]Plugins ({len(result.plugins)}):[/bold cyan]")
            for plugin in result.plugins[:20]:
                status = "[green]active[/green]" if plugin.active else "[red]inactive[/red]"
                console.print(f"  - {plugin.short_name} v{plugin.version} ({status})")
            if len(result.plugins) > 20:
                console.print(f"  ... and {len(result.plugins) - 20} more")

        if result.jobs:
            console.print(f"\n[bold cyan]Jobs ({len(result.jobs)}):[/bold cyan]")
            for job in result.jobs[:20]:
                console.print(f"  - {job.name}")
            if len(result.jobs) > 20:
                console.print(f"  ... and {len(result.jobs) - 20} more")

        if result.vulnerabilities:
            console.print(f"\n[bold red]Vulnerabilities ({len(result.vulnerabilities)}):[/bold red]")
            for vuln in result.vulnerabilities:
                console.print(f"  - [bold]{vuln.get('cve', 'N/A')}[/bold]: {vuln.get('description', 'N/A')}")

        session.close()
        return 0

    except Exception as e:
        logger.error(f"Enumeration failed: {e}", exc_info=args.verbose)
        return 1


def cmd_exploit(args: argparse.Namespace) -> int:
    """Execute exploit command."""
    logger = setup_logging(
        level=logging.DEBUG if args.verbose else logging.INFO,
        log_file=args.log_file,
        console_output=not args.quiet
    )

    try:
        config = SessionConfig(
            url=args.url,
            username=args.username,
            password=args.password,
            proxy=args.proxy,
            delay=args.delay,
            timeout=args.timeout
        )

        session = JenkinsSession(config)

        if not session.connect():
            logger.error(f"Failed to connect to {args.url}")
            return 1

        logger.success(f"Connected to Jenkins at {args.url}")

        exploit_module = exploit_registry.get(args.cve_id)

        if not exploit_module:
            logger.error(f"Exploit not found: {args.cve_id}")
            logger.info(f"Available exploits: {', '.join(exploit_registry.list_cves())}")
            return 1

        metadata = exploit_registry.get_metadata(args.cve_id)
        logger.info(f"Executing {metadata.name} ({args.cve_id})")

        kwargs = {}
        if args.lhost:
            kwargs['lhost'] = args.lhost
        if args.lport:
            kwargs['lport'] = args.lport
        if args.command:
            kwargs['command'] = args.command

        if exploit_module.check_vulnerable(session, **kwargs):
            logger.info("Target appears vulnerable")
        else:
            logger.warning("Target may not be vulnerable")
            if not args.force:
                logger.info("Use --force to attempt anyway")
                return 1

        logger.exploit_start(args.cve_id, args.url)
        result = exploit_module.run(session, **kwargs)

        if result.status == "success":
            logger.exploit_success(args.cve_id, result.details)
            return 0
        else:
            logger.exploit_failure(args.cve_id, result.error or result.details)
            return 1

    except Exception as e:
        logger.error(f"Exploit failed: {e}", exc_info=args.verbose)
        return 1
    finally:
        session.close()


def cmd_list(args: argparse.Namespace) -> int:
    """List available exploits."""
    setup_logging(console_output=not args.quiet)

    exploits = exploit_registry.list_all()

    if not exploits:
        console.print("[yellow]No exploits loaded[/yellow]")
        return 1

    console.print(f"[bold cyan]Available Exploits ({len(exploits)}):[/bold cyan]\n")

    for cve, metadata in sorted(exploits.items()):
        severity_color = {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue'
        }.get(metadata.severity.lower(), 'white')

        console.print(f"[bold]{cve}[/bold]")
        console.print(f"  Name: {metadata.name}")
        console.print(f"  Severity: [{severity_color}]{metadata.severity.upper()}[/{severity_color}]")
        console.print(f"  Description: {metadata.description}")
        console.print(f"  Requires Auth: {'Yes' if metadata.requires_auth else 'No'}")
        console.print()

    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Generate example configuration."""
    setup_logging(console_output=not args.quiet)

    try:
        output_path = args.output or "config/example.yaml"
        ConfigLoader.create_example(output_path)
        console.print(f"[green]Example configuration created: {output_path}[/green]")
        return 0
    except Exception as e:
        console.print(f"[red]Failed to create config: {e}[/red]")
        return 1


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="jenkins-breaker",
        description="CI/CD Exploitation Framework for Jenkins Infrastructure Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--version",
        action="version",
        version="JenkinsBreaker 2.0.0"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    enumerate_parser = subparsers.add_parser(
        "enumerate",
        help="Enumerate Jenkins instance"
    )
    enumerate_parser.add_argument("--url", required=True, help="Jenkins URL")
    enumerate_parser.add_argument("--username", help="Username")
    enumerate_parser.add_argument("--password", help="Password")
    enumerate_parser.add_argument("--proxy", help="Proxy URL")
    enumerate_parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    enumerate_parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    enumerate_parser.add_argument("--log-file", help="Log file path")
    enumerate_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    enumerate_parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    enumerate_parser.set_defaults(func=cmd_enumerate)

    exploit_parser = subparsers.add_parser(
        "exploit",
        help="Execute exploit"
    )
    exploit_parser.add_argument("cve_id", help="CVE ID (e.g., CVE-2024-23897)")
    exploit_parser.add_argument("--url", required=True, help="Jenkins URL")
    exploit_parser.add_argument("--username", help="Username")
    exploit_parser.add_argument("--password", help="Password")
    exploit_parser.add_argument("--lhost", help="Local host for callback")
    exploit_parser.add_argument("--lport", type=int, help="Local port for callback")
    exploit_parser.add_argument("--command", help="Command to execute")
    exploit_parser.add_argument("--proxy", help="Proxy URL")
    exploit_parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    exploit_parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    exploit_parser.add_argument("--force", action="store_true", help="Force exploit even if not vulnerable")
    exploit_parser.add_argument("--log-file", help="Log file path")
    exploit_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    exploit_parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    exploit_parser.set_defaults(func=cmd_exploit)

    list_parser = subparsers.add_parser(
        "list",
        help="List available exploits"
    )
    list_parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    list_parser.set_defaults(func=cmd_list)

    config_parser = subparsers.add_parser(
        "config",
        help="Generate example configuration"
    )
    config_parser.add_argument("--output", "-o", help="Output file path")
    config_parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    config_parser.set_defaults(func=cmd_config)

    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not hasattr(args, 'func'):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
