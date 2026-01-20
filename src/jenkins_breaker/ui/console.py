"""
Interactive REPL console for JenkinsBreaker with command completion and context awareness.
Provides an operator-focused command-line interface similar to professional penetration testing frameworks.
"""

import os
from pathlib import Path
from typing import Any, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.table import Table

from jenkins_breaker.core.enumeration import JenkinsEnumerator
from jenkins_breaker.core.session import JenkinsSession, SessionConfig
from jenkins_breaker.modules.base import exploit_registry
from jenkins_breaker.post.reverse_shell import ReverseShellListener
from jenkins_breaker.post.session_manager import session_manager
from jenkins_breaker.post.shell import InteractiveShell
from jenkins_breaker.ui.loot import LootManager
from jenkins_breaker.ui.manager import JobManager
from jenkins_breaker.ui.shared_state import shared_state
from jenkins_breaker.ui.ui_bridge import ui_bridge
from jenkins_breaker.utils.logger import console, setup_logging

import jenkins_breaker.ui.ops_scripts.escalate as escalate_scripts
import jenkins_breaker.ui.ops_scripts.harvest as harvest_scripts
import jenkins_breaker.ui.ops_scripts.lateral as lateral_scripts
import jenkins_breaker.ui.ops_scripts.persist as persist_scripts
import jenkins_breaker.ui.ops_scripts.situational as situational_scripts
import jenkins_breaker.ui.ops_scripts.exfiltrate as exfiltrate_scripts
import jenkins_breaker.ui.ops_scripts.utility as utility_scripts

OPERATOR_SCRIPTS = {
    'escalate': escalate_scripts,
    'harvest': harvest_scripts,
    'lateral': lateral_scripts,
    'persist': persist_scripts,
    'situational': situational_scripts,
    'exfiltrate': exfiltrate_scripts,
    'utility': utility_scripts,
}


class JenkinsConsoleCompleter(Completer):
    """Context-aware tab completion for console commands."""

    def __init__(self, console_instance: 'JenkinsConsole'):
        self.console = console_instance
        self.base_commands = [
            'use', 'set', 'unset', 'show', 'run', 'exploit',
            'background', 'jobs', 'sessions', 'kill',
            'enumerate', 'connect', 'disconnect',
            'loot', 'export', 'search',
            'record', 'replay', 'save',
            'listener', 'shell', 'interact',
            'escalate', 'harvest', 'lateral', 'persist',
            'situational', 'exfiltrate', 'utility',
            'tui', 'webui', 'console',
            'help', 'exit', 'quit', 'clear'
        ]

    def get_completions(self, document, complete_event):
        word_before_cursor = document.get_word_before_cursor()
        line = document.text_before_cursor
        words = line.split()

        if not words or (len(words) == 1 and not line.endswith(' ')):
            for cmd in self.base_commands:
                if cmd.startswith(word_before_cursor):
                    yield Completion(cmd, start_position=-len(word_before_cursor))

        elif words[0] == 'use':
            cves = exploit_registry.list_cves()
            for cve in cves:
                if cve.lower().startswith(word_before_cursor.lower()):
                    yield Completion(cve, start_position=-len(word_before_cursor))

        elif words[0] == 'set':
            if len(words) == 1 or (len(words) == 2 and not line.endswith(' ')):
                options = ['target', 'username', 'password', 'proxy', 'lhost', 'lport', 'command', 'delay', 'timeout', 'handler']
                for opt in options:
                    if opt.startswith(word_before_cursor.lower()):
                        yield Completion(opt, start_position=-len(word_before_cursor))

        elif words[0] == 'listener':
            if len(words) == 1 or (len(words) == 2 and not line.endswith(' ')):
                options = ['start', 'stop', 'status']
                for opt in options:
                    if opt.startswith(word_before_cursor.lower()):
                        yield Completion(opt, start_position=-len(word_before_cursor))

        elif words[0] == 'shell':
            if len(words) == 1 or (len(words) == 2 and not line.endswith(' ')):
                options = ['spawn', 'interact']
                for opt in options:
                    if opt.startswith(word_before_cursor.lower()):
                        yield Completion(opt, start_position=-len(word_before_cursor))

        elif words[0] == 'show':
            if len(words) == 1 or (len(words) == 2 and not line.endswith(' ')):
                options = ['options', 'exploits', 'jobs', 'loot', 'info', 'targets']
                for opt in options:
                    if opt.startswith(word_before_cursor.lower()):
                        yield Completion(opt, start_position=-len(word_before_cursor))

        elif words[0] in ['jobs', 'kill', 'sessions']:
            if self.console.job_manager:
                job_ids = [str(jid) for jid in self.console.job_manager.list_jobs().keys()]
                for jid in job_ids:
                    if jid.startswith(word_before_cursor):
                        yield Completion(jid, start_position=-len(word_before_cursor))

        elif words[0] in ['escalate', 'harvest', 'lateral', 'persist', 'situational', 'exfiltrate', 'utility']:
            if len(words) == 1 or (len(words) == 2 and not line.endswith(' ')):
                category = words[0]
                script_names = self.console._get_operator_script_names(category)
                for script_name in script_names:
                    if script_name.lower().startswith(word_before_cursor.lower()):
                        yield Completion(script_name, start_position=-len(word_before_cursor))


class JenkinsConsole:
    """
    Interactive command console for Jenkins exploitation.

    Provides a REPL interface with:
    - Tab completion for commands and CVE IDs
    - Command history persistence
    - Context-aware command execution
    - Background job management
    - Session recording
    """

    def __init__(self):
        self.session: Optional[JenkinsSession] = None
        self.current_exploit = None
        self.current_shell_session = None
        self.options: dict[str, Any] = {
            'target': None,
            'username': None,
            'password': None,
            'proxy': None,
            'lhost': None,
            'lport': 4444,
            'command': None,
            'delay': 0.0,
            'timeout': 10,
            'handler': 'auto',
        }

        self.job_manager = JobManager()
        self.loot_manager = LootManager()
        self.recording = False
        self.macro_commands: list[str] = []
        self.active_listener: Optional[ReverseShellListener] = None
        self.listener_thread: Optional[Any] = None

        history_dir = Path.home() / '.jenkins_breaker'
        history_dir.mkdir(exist_ok=True)
        self.history_file = history_dir / 'console_history'

        self.style = Style.from_dict({
            'prompt': '#00ff41 bold',
            'exploit': '#ff8800 bold',
        })

        setup_logging(console_output=True)

    def get_prompt(self) -> HTML:
        """Generate context-aware prompt."""
        if self.current_exploit:
            return HTML(f'<prompt>jb</prompt> <exploit>({self.current_exploit})</exploit> > ')
        return HTML('<prompt>jb</prompt> > ')

    def print_banner(self):
        """Display console banner."""
        console.print("[bold cyan]JenkinsBreaker Interactive Console[/bold cyan]")
        console.print(f"[dim]Loaded {len(exploit_registry.list_cves())} exploit modules[/dim]")
        console.print("[dim]Type 'help' for available commands[/dim]\n")

    def cmd_help(self, args: list[str]):
        """Display help information."""
        table = Table(title="Available Commands", show_header=True, header_style="bold cyan")
        table.add_column("Command", style="cyan", width=20)
        table.add_column("Description", style="white")

        commands = [
            ("use <cve>", "Select an exploit module"),
            ("set <option> <value>", "Set an option value"),
            ("unset <option>", "Clear an option value"),
            ("show <type>", "Display options, exploits, jobs, or loot"),
            ("run / exploit", "Execute the current exploit"),
            ("background", "Background the current exploit"),
            ("jobs", "List background jobs"),
            ("kill <id>", "Kill a background job"),
            ("sessions [-a|-d]", "List sessions (-a: all, -d: debug)"),
            ("connect", "Connect to target Jenkins instance"),
            ("disconnect", "Close current session"),
            ("enumerate", "Enumerate target information"),
            ("listener <action>", "Start/stop reverse shell listener"),
            ("shell spawn", "Spawn interactive shell on compromised target"),
            ("interact", "Interact with compromised target (alias for shell)"),
            ("loot", "Browse captured credentials and artifacts"),
            ("search <term>", "Search for exploits"),
            ("record", "Start/stop macro recording"),
            ("replay <file>", "Replay a recorded macro"),
            ("save <file>", "Save current session state"),
            ("tui", "Launch TUI interface in new window"),
            ("webui [port]", "Launch Web UI interface (default port: 8000)"),
            ("", ""),
            ("OPERATOR SCRIPTS", ""),
            ("escalate [script]", "Privilege escalation scripts"),
            ("harvest [script]", "Credential harvesting scripts"),
            ("lateral [script]", "Lateral movement scripts"),
            ("persist [script]", "Persistence establishment scripts"),
            ("situational [script]", "Situational awareness scripts"),
            ("exfiltrate [script]", "Data exfiltration scripts"),
            ("utility [script]", "Utility scripts"),
            ("", ""),
            ("clear", "Clear the screen"),
            ("exit / quit", "Exit console"),
        ]

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        console.print(table)

    def cmd_use(self, args: list[str]):
        """Select an exploit module."""
        if not args:
            console.print("[red]Usage: use <cve_id>[/red]")
            return

        cve_id = args[0].upper()
        if cve_id not in exploit_registry.list_cves():
            console.print(f"[red]Exploit not found: {cve_id}[/red]")
            console.print("[yellow]Use 'show exploits' to list available exploits[/yellow]")
            return

        self.current_exploit = cve_id
        metadata = exploit_registry.get_metadata(cve_id)

        console.print(f"[green]Selected exploit: {cve_id}[/green]")
        console.print(f"[dim]Name: {metadata.name}[/dim]")
        console.print(f"[dim]Severity: {metadata.severity.upper()}[/dim]")
        console.print(f"[dim]Requires Auth: {'Yes' if metadata.requires_auth else 'No'}[/dim]")

    def cmd_set(self, args: list[str]):
        """Set an option value."""
        if len(args) < 2:
            console.print("[red]Usage: set <option> <value>[/red]")
            return

        option = args[0].lower()
        value = ' '.join(args[1:])

        if option not in self.options:
            console.print(f"[red]Unknown option: {option}[/red]")
            return

        if option in ['lport', 'timeout']:
            try:
                value = int(value)
            except ValueError:
                console.print(f"[red]{option} must be an integer[/red]")
                return
        elif option == 'delay':
            try:
                value = float(value)
            except ValueError:
                console.print(f"[red]{option} must be a number[/red]")
                return

        self.options[option] = value
        console.print(f"[green]{option} => {value}[/green]")

    def cmd_unset(self, args: list[str]):
        """Clear an option value."""
        if not args:
            console.print("[red]Usage: unset <option>[/red]")
            return

        option = args[0].lower()
        if option not in self.options:
            console.print(f"[red]Unknown option: {option}[/red]")
            return

        self.options[option] = None
        console.print(f"[green]Cleared {option}[/green]")

    def cmd_show(self, args: list[str]):
        """Display information."""
        if not args:
            args = ['options']

        show_type = args[0].lower()

        if show_type == 'options':
            table = Table(title="Current Options", show_header=True, header_style="bold cyan")
            table.add_column("Option", style="cyan")
            table.add_column("Value", style="green")
            table.add_column("Required", style="yellow")

            required = ['target'] if not self.session else []
            if self.current_exploit:
                metadata = exploit_registry.get_metadata(self.current_exploit)
                if metadata.requires_auth:
                    required.extend(['username', 'password'])

            for opt, val in self.options.items():
                req = "Yes" if opt in required else "No"
                val_str = str(val) if val is not None else ""
                table.add_row(opt, val_str, req)

            console.print(table)

        elif show_type == 'exploits':
            table = Table(title="Available Exploits", show_header=True, header_style="bold cyan")
            table.add_column("CVE", style="cyan", width=20)
            table.add_column("Name", style="white", width=40)
            table.add_column("Severity", style="red", width=10)

            exploits = exploit_registry.list_all()
            for cve_id, metadata in sorted(exploits.items()):
                severity_color = {
                    'critical': 'bold red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'blue'
                }.get(metadata.severity.lower(), 'white')

                table.add_row(
                    cve_id,
                    metadata.name,
                    f"[{severity_color}]{metadata.severity.upper()}[/{severity_color}]"
                )

            console.print(table)

        elif show_type == 'jobs':
            jobs = self.job_manager.list_jobs()
            if not jobs:
                console.print("[yellow]No background jobs[/yellow]")
                return

            table = Table(title="Background Jobs", show_header=True, header_style="bold cyan")
            table.add_column("ID", style="cyan")
            table.add_column("Exploit", style="white")
            table.add_column("Status", style="green")
            table.add_column("Started", style="dim")

            for job_id, job_info in jobs.items():
                table.add_row(
                    str(job_id),
                    job_info['exploit'],
                    job_info['status'],
                    job_info['started']
                )

            console.print(table)

        elif show_type == 'loot':
            self.loot_manager.display_summary()

        elif show_type == 'sessions':
            self.cmd_sessions([])

        elif show_type == 'info':
            if not self.current_exploit:
                console.print("[red]No exploit selected. Use 'use <cve>' first[/red]")
                return

            metadata = exploit_registry.get_metadata(self.current_exploit)
            console.print(f"\n[bold cyan]{metadata.cve_id}[/bold cyan]")
            console.print(f"[white]Name:[/white] {metadata.name}")
            console.print(f"[white]Description:[/white] {metadata.description}")
            console.print(f"[white]Severity:[/white] {metadata.severity.upper()}")
            console.print(f"[white]Affected Versions:[/white] {', '.join(metadata.affected_versions)}")
            console.print(f"[white]MITRE ATT&CK:[/white] {', '.join(metadata.mitre_attack)}")
            console.print(f"[white]Requires Auth:[/white] {'Yes' if metadata.requires_auth else 'No'}")
            console.print(f"[white]Requires Crumb:[/white] {'Yes' if metadata.requires_crumb else 'No'}")
            if metadata.references:
                console.print("[white]References:[/white]")
                for ref in metadata.references:
                    console.print(f"  - {ref}")

        else:
            console.print(f"[red]Unknown show type: {show_type}[/red]")
            console.print("[yellow]Available: options, exploits, jobs, loot, sessions, info[/yellow]")

    def cmd_connect(self, args: list[str]):
        """Connect to target Jenkins instance."""
        if not self.options['target']:
            console.print("[red]Target not set. Use 'set target <url>' first[/red]")
            return

        try:
            config = SessionConfig(
                url=self.options['target'],
                username=self.options['username'],
                password=self.options['password'],
                proxy=self.options['proxy'],
                delay=self.options['delay'] or 0.0,
                timeout=self.options['timeout'] or 10,
                verify_ssl=False
            )

            console.print(f"[cyan]Connecting to {self.options['target']}...[/cyan]")
            self.session = JenkinsSession(config)

            if self.session.connect():
                version = self.session.version or "Unknown"
                console.print(f"[green]Connected to Jenkins {version}[/green]")

                if self.session.is_authenticated:
                    console.print(f"[green]Authenticated as {self.options['username']}[/green]")
            else:
                console.print("[red]Connection failed[/red]")
                self.session = None

        except Exception as e:
            console.print(f"[red]Connection error: {e}[/red]")
            self.session = None

    def cmd_disconnect(self, args: list[str]):
        """Close current session."""
        if self.session:
            self.session.close()
            self.session = None
            console.print("[green]Session closed[/green]")
        else:
            console.print("[yellow]No active session[/yellow]")

    def cmd_enumerate(self, args: list[str]):
        """Enumerate target information."""
        if not self.session:
            console.print("[red]Not connected. Use 'connect' first[/red]")
            return

        console.print("[cyan]Enumerating target...[/cyan]")

        try:
            enumerator = JenkinsEnumerator(
                base_url=self.session.base_url,
                auth=self.session.auth,
                proxies={},
                verify_ssl=False,
                timeout=self.options['timeout'] or 10,
                delay=self.options['delay'] or 0.0
            )

            result = enumerator.enumerate_all()

            if result.version:
                console.print(f"[green]Version: {result.version.version}[/green]")

            if result.plugins:
                console.print(f"[green]Plugins: {len(result.plugins)}[/green]")

            if result.jobs:
                console.print(f"[green]Jobs: {len(result.jobs)}[/green]")

            if result.vulnerabilities:
                console.print(f"[yellow]Potential vulnerabilities: {len(result.vulnerabilities)}[/yellow]")

        except Exception as e:
            console.print(f"[red]Enumeration failed: {e}[/red]")

    def cmd_run(self, args: list[str]):
        """Execute the current exploit."""
        if not self.current_exploit:
            console.print("[red]No exploit selected. Use 'use <cve>' first[/red]")
            return

        if not self.session:
            console.print("[red]Not connected. Use 'connect' first[/red]")
            return

        metadata = exploit_registry.get_metadata(self.current_exploit)

        if metadata.requires_auth and not self.session.is_authenticated:
            console.print("[red]This exploit requires authentication[/red]")
            return

        exploit_module = exploit_registry.get(self.current_exploit)

        kwargs = {}
        if self.options['lhost']:
            kwargs['lhost'] = self.options['lhost']
        if self.options['lport']:
            kwargs['lport'] = self.options['lport']
        if self.options['command']:
            kwargs['command'] = self.options['command']
        if self.options['handler']:
            kwargs['handler'] = self.options['handler']

        lhost = self.options.get('lhost')
        lport = self.options.get('lport', 4444)
        handler = self.options.get('handler', 'auto')
        
        using_external_handler = handler in ['nc', 'netcat', 'ncat', 'msfconsole', 'msf']
        
        if lhost and not using_external_handler:
            if not self.active_listener or not self.listener_thread or not self.listener_thread.is_alive():
                console.print("[yellow]No listener running - starting automatically...[/yellow]")
                self.cmd_listener(['start'])
                import time
                time.sleep(1)

        console.print(f"[cyan]Executing {self.current_exploit}...[/cyan]")

        try:
            sessions_before = len(session_manager.list_active_sessions())
            
            result = exploit_module.run(self.session, **kwargs)

            if result.status == "success":
                console.print(f"[green]Exploit successful: {result.details}[/green]")
                if result.data:
                    self.loot_manager.add_loot(self.current_exploit, result.data)
                
                if using_external_handler:
                    console.print(f"[cyan]Using external handler: {handler}[/cyan]")
                    console.print(f"[yellow]Check your {handler} listener at {lhost}:{lport} for shell connection[/yellow]")
                    console.print("[dim]Note: External handler sessions won't appear in 'sessions' list[/dim]")
                else:
                    console.print("[cyan]Waiting for shell connection (10 seconds)...[/cyan]")
                    import time
                    for i in range(20):
                        time.sleep(0.5)
                        sessions_after = len(session_manager.list_active_sessions())
                        if sessions_after > sessions_before:
                            console.print(f"[green]✓ Shell connected! ({sessions_after - sessions_before} new session(s))[/green]")
                            console.print("[cyan]Use 'sessions' to list active sessions[/cyan]")
                            console.print("[cyan]Use 'interact <id>' to interact with a session[/cyan]")
                            break
                    else:
                        sessions_after = len(session_manager.list_active_sessions())
                        if sessions_after == sessions_before:
                            console.print(f"[yellow]No shell received after 10 seconds (sessions: {sessions_before})[/yellow]")
                            console.print("[dim]Shell may still connect later - use 'sessions' to check[/dim]")
                    
            else:
                console.print(f"[red]Exploit failed: {result.details}[/red]")

        except Exception as e:
            console.print(f"[red]Execution error: {e}[/red]")

    def cmd_background(self, args: list[str]):
        """Background the current exploit."""
        if not self.current_exploit:
            console.print("[red]No exploit selected[/red]")
            return

        if not self.session:
            console.print("[red]Not connected[/red]")
            return

        job_id = self.job_manager.start_job(
            exploit=self.current_exploit,
            session=self.session,
            options=self.options.copy()
        )

        console.print(f"[green]Started background job {job_id}[/green]")

    def cmd_jobs(self, args: list[str]):
        """List background jobs."""
        self.cmd_show(['jobs'])

    def cmd_kill(self, args: list[str]):
        """Kill a background job."""
        if not args:
            console.print("[red]Usage: kill <job_id>[/red]")
            return

        try:
            job_id = int(args[0])
            if self.job_manager.kill_job(job_id):
                console.print(f"[green]Killed job {job_id}[/green]")
            else:
                console.print(f"[red]Job {job_id} not found[/red]")
        except ValueError:
            console.print("[red]Job ID must be a number[/red]")

    def cmd_search(self, args: list[str]):
        """Search for exploits."""
        if not args:
            console.print("[red]Usage: search <term>[/red]")
            return

        term = ' '.join(args).lower()
        exploits = exploit_registry.list_all()
        matches = []

        for cve_id, metadata in exploits.items():
            if (term in cve_id.lower() or
                term in metadata.name.lower() or
                term in metadata.description.lower()):
                matches.append((cve_id, metadata))

        if not matches:
            console.print(f"[yellow]No exploits found matching '{term}'[/yellow]")
            return

        table = Table(title=f"Search Results for '{term}'", show_header=True, header_style="bold cyan")
        table.add_column("CVE", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Severity", style="red")

        for cve_id, metadata in matches:
            table.add_row(cve_id, metadata.name, metadata.severity.upper())

        console.print(table)

    def cmd_record(self, args: list[str]):
        """Start/stop macro recording."""
        self.recording = not self.recording

        if self.recording:
            self.macro_commands = []
            console.print("[green]Started recording macro[/green]")
        else:
            console.print("[green]Stopped recording[/green]")
            if self.macro_commands:
                console.print(f"[dim]Recorded {len(self.macro_commands)} commands[/dim]")

    def cmd_clear(self, args: list[str]):
        """Clear the screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def cmd_listener(self, args: list[str]):
        """Start a reverse shell listener."""
        if not args or args[0] not in ['start', 'stop', 'status']:
            console.print("[yellow]Usage: listener <start|stop|status>[/yellow]")
            console.print("[cyan]Examples:[/cyan]")
            console.print("  listener start     - Start listener on configured lhost:lport")
            console.print("  listener stop      - Stop running listener")
            console.print("  listener status    - Show listener configuration")
            return

        action = args[0]

        if action == 'start':
            if self.active_listener and self.listener_thread and self.listener_thread.is_alive():
                console.print("[yellow]Listener already running[/yellow]")
                console.print("[dim]Use 'listener stop' to stop it first[/dim]")
                return
            
            if self.active_listener and (not self.listener_thread or not self.listener_thread.is_alive()):
                console.print("[dim]Cleaning up dead listener...[/dim]")
                self.active_listener = None
                self.listener_thread = None

            lhost = self.options.get('lhost', '0.0.0.0')
            lport = self.options.get('lport', 4444)
            handler = self.options.get('handler', 'auto')

            if not lhost:
                console.print("[red]Error: lhost not set[/red]")
                console.print("[yellow]Use: set lhost <ip>[/yellow]")
                return

            import socket
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(1)
            bind_host = lhost if lhost != "0.0.0.0" else "127.0.0.1"
            try:
                result = test_sock.connect_ex((bind_host, lport))
                test_sock.close()
                if result == 0:
                    console.print(f"[red]Port {lport} already in use![/red]")
                    console.print(f"[yellow]Detected existing listener on {bind_host}:{lport}[/yellow]")
                    console.print("[cyan]Options:[/cyan]")
                    console.print("  1. Set handler to 'ncat' to use external listener: set handler ncat")
                    console.print("  2. Stop external listener and retry")
                    console.print("  3. Use different port: set lport <port>")
                    return
            except:
                pass

            console.print("[cyan]Starting reverse shell listener...[/cyan]")
            console.print(f"[cyan]Host: {lhost}[/cyan]")
            console.print(f"[cyan]Port: {lport}[/cyan]")
            console.print(f"[cyan]Handler: {handler}[/cyan]")

            def connection_callback(conn, addr, session_id):
                """Called when shell connects"""
                console.print(f"\n[bold green]✓ Shell connected from {addr[0]}:{addr[1]}![/bold green]")
                console.print(f"[cyan]Session ID: {session_id[:8]}...[/cyan]")
                console.print("[dim]Use 'sessions' to list, 'interact <id>' to interact[/dim]\n")

            try:
                import threading
                self.active_listener = ReverseShellListener(lhost, lport, handler=handler)
                
                def listener_thread_func():
                    self.active_listener.start(callback=connection_callback)
                
                self.listener_thread = threading.Thread(target=listener_thread_func, daemon=True)
                self.listener_thread.start()
                
                import time
                time.sleep(0.5)
                
                if self.listener_thread.is_alive():
                    console.print(f"[green]✓ Listener running in background on {lhost}:{lport}[/green]")
                    console.print("[dim]Listener will accept connections automatically[/dim]\n")
                else:
                    console.print("[red]Failed to start listener thread[/red]")
                    self.active_listener = None
                    self.listener_thread = None
                    
            except Exception as e:
                console.print(f"[red]Failed to start listener: {e}[/red]")
                self.active_listener = None
                self.listener_thread = None

        elif action == 'stop':
            if not self.active_listener or not self.listener_thread or not self.listener_thread.is_alive():
                console.print("[yellow]No listener running[/yellow]")
                return
            
            try:
                self.active_listener.running = False
                self.active_listener = None
                self.listener_thread = None
                console.print("[green]Listener stopped[/green]")
            except Exception as e:
                console.print(f"[red]Error stopping listener: {e}[/red]")

        elif action == 'status':
            lhost = self.options.get('lhost', 'Not set')
            lport = self.options.get('lport', 4444)
            handler = self.options.get('handler', 'auto')
            
            using_external = handler in ['nc', 'netcat', 'ncat', 'msfconsole', 'msf']

            console.print("[cyan]Listener Configuration:[/cyan]")
            console.print(f"  LHOST:   {lhost}")
            console.print(f"  LPORT:   {lport}")
            console.print(f"  HANDLER: {handler}")
            
            if using_external:
                console.print(f"\n[yellow]External handler mode: {handler}[/yellow]")
                console.print("[dim]Console expects you to run external listener manually[/dim]")
            elif self.active_listener and self.listener_thread and self.listener_thread.is_alive():
                console.print(f"\n[green]Status: RUNNING (Python built-in)[/green]")
            else:
                console.print(f"\n[yellow]Status: NOT RUNNING[/yellow]")

    def cmd_shell(self, args: list[str]):
        """Spawn an interactive shell."""
        if not args or args[0] not in ['spawn', 'interact']:
            console.print("[yellow]Usage: shell <spawn|interact>[/yellow]")
            console.print("[cyan]Examples:[/cyan]")
            console.print("  shell spawn      - Spawn interactive shell (requires active session)")
            console.print("  shell interact   - Alias for spawn")
            return

        if not self.session:
            console.print("[red]No active session. Use 'connect' first[/red]")
            return

        method = self.options.get('method', 'script_console')

        console.print(f"[cyan]Spawning interactive shell via {method}...[/cyan]\n")

        shell = InteractiveShell(self.session, method)
        shell.start_interactive()

    def cmd_sessions(self, args: list[str]):
        """List active shell sessions."""
        show_all = args and args[0] == '-a'
        show_debug = args and args[0] == '-d'
        
        all_sessions = session_manager.list_sessions()
        sessions_dict = session_manager.list_active_sessions() if not show_all and not show_debug else all_sessions
        
        if not all_sessions:
            console.print("[yellow]No sessions registered[/yellow]")
            console.print("[dim]Sessions will appear here after exploits spawn shells[/dim]")
            return
        
        if not sessions_dict:
            console.print(f"[yellow]No active sessions ({len(all_sessions)} total registered)[/yellow]")
            console.print("[dim]Showing all registered sessions with -a flag:[/dim]\n")
            sessions_dict = all_sessions
        
        active_count = len(session_manager.list_active_sessions())
        console.print(f"[dim]Total: {len(all_sessions)} | Active: {active_count} | Showing: {len(sessions_dict)}[/dim]")
        
        if show_debug:
            console.print(f"[dim]Session timeout: {session_manager.session_timeout}s[/dim]\n")
        
        title = "Debug Sessions" if show_debug else ("All Sessions" if show_all else "Active Sessions")
        table = Table(title=title, show_header=True, header_style="bold cyan")
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Host", style="white", width=15)
        table.add_column("Port", style="white", width=6)
        table.add_column("Type", style="green", width=10)
        table.add_column("User@Host", style="yellow", width=20)
        table.add_column("Status", style="white", width=14)
        table.add_column("Uptime", style="dim", width=10)
        
        if show_debug:
            table.add_column("Last Seen", style="dim", width=12)
        
        for session_id, session in sessions_dict.items():
            import datetime
            alive_check = session.is_alive(session_manager.session_timeout)
            alive = "✓" if alive_check else "✗"
            status_display = f"{alive} {session.status.value}"
            
            row_data = [
                session.session_id,
                session.remote_host,
                str(session.remote_port),
                session.shell_type.value,
                f"{session.username or '?'}@{session.hostname or '?'}",
                status_display,
                session.get_uptime()
            ]
            
            if show_debug:
                time_since = (datetime.datetime.now() - session.last_seen).total_seconds()
                row_data.append(f"{time_since:.0f}s ago")
            
            table.add_row(*row_data)
        
        console.print(table)
        
        if show_debug:
            console.print("\n[cyan]Debug Info:[/cyan]")
            for session_id, session in sessions_dict.items():
                import datetime
                time_since = (datetime.datetime.now() - session.last_seen).total_seconds()
                alive_check = session.is_alive(session_manager.session_timeout)
                console.print(f"  [{session_id}] Status={session.status.value}, LastSeen={time_since:.1f}s, IsAlive={alive_check}, Timeout={session_manager.session_timeout}s")
                if not alive_check and session.status != "dead":
                    reason = "status=DEAD" if session.status.value == "dead" else f"timeout (last_seen {time_since:.0f}s > {session_manager.session_timeout}s)"
                    console.print(f"    [yellow]Not alive: {reason}[/yellow]")
        
        if not show_all and not show_debug and active_count < len(all_sessions):
            console.print(f"\n[dim]Tip: Use 'sessions -a' to show all {len(all_sessions)} sessions (including inactive)[/dim]")
            console.print(f"[dim]Tip: Use 'sessions -d' for debug info on why sessions aren't active[/dim]")
        console.print(f"[dim]Use 'interact <id>' to interact with a session[/dim]")
    
    def cmd_interact(self, args: list[str]):
        """Interact with a shell session."""
        if not args:
            sessions_dict = session_manager.list_active_sessions()
            if len(sessions_dict) == 1:
                session_id = list(sessions_dict.keys())[0]
                console.print(f"[cyan]Auto-selecting session {session_id}...[/cyan]")
            else:
                console.print("[red]Usage: interact <session_id>[/red]")
                console.print("[yellow]Use 'sessions' to list available sessions[/yellow]")
                return
        else:
            session_id_prefix = args[0]
            sessions_dict = session_manager.list_active_sessions()
            matching = [sid for sid in sessions_dict.keys() if sid.startswith(session_id_prefix)]
            
            if not matching:
                console.print(f"[red]No session found matching '{session_id_prefix}'[/red]")
                console.print("[yellow]Use 'sessions' to list available sessions[/yellow]")
                return
            
            if len(matching) > 1:
                console.print(f"[red]Multiple sessions match '{session_id_prefix}', be more specific[/red]")
                return
            
            session_id = matching[0]
        
        session_meta = session_manager.get_session(session_id)
        if not session_meta:
            console.print(f"[red]Session {session_id} not found[/red]")
            return
        
        if not session_meta.connection:
            console.print(f"[red]Session {session_id} has no active connection[/red]")
            return
        
        console.print(f"[green]Interacting with session {session_id}...[/green]")
        console.print("[dim]Use Ctrl+C to background session[/dim]\n")
        
        try:
            self._interactive_shell(session_id, session_meta.connection)
        except KeyboardInterrupt:
            console.print("\n[yellow]Session backgrounded[/yellow]")
            session_manager.background_current_session()
        except Exception as e:
            console.print(f"[red]Error interacting with session: {e}[/red]")
    
    def _interactive_shell(self, session_id: str, conn):
        """Handle interactive shell session."""
        import sys
        
        session_manager.set_current_session(session_id)
        
        if sys.platform == "win32":
            import msvcrt
            conn.setblocking(False)
            
            try:
                while True:
                    if msvcrt.kbhit():
                        char = msvcrt.getch()
                        if char == b'\x03':
                            raise KeyboardInterrupt
                        conn.sendall(char)
                    
                    try:
                        data = conn.recv(4096)
                        if data:
                            sys.stdout.write(data.decode('utf-8', errors='ignore'))
                            sys.stdout.flush()
                        else:
                            break
                    except BlockingIOError:
                        pass
                    except Exception:
                        break
                    
                    import time
                    time.sleep(0.01)
            finally:
                conn.setblocking(True)
        else:
            import select
            import tty
            import termios
            
            old_settings = termios.tcgetattr(sys.stdin)
            try:
                tty.setraw(sys.stdin.fileno())
                conn.setblocking(False)
                
                while True:
                    readable, _, _ = select.select([sys.stdin, conn], [], [], 0.1)
                    
                    if sys.stdin in readable:
                        char = sys.stdin.read(1)
                        if char == '\x03':
                            raise KeyboardInterrupt
                        conn.sendall(char.encode())
                    
                    if conn in readable:
                        try:
                            data = conn.recv(4096)
                            if data:
                                sys.stdout.write(data.decode('utf-8', errors='ignore'))
                                sys.stdout.flush()
                            else:
                                break
                        except:
                            break
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                conn.setblocking(True)

    def cmd_tui(self, args: list[str]):
        """Launch TUI interface in new window."""
        console.print("[cyan]Launching TUI interface...[/cyan]")
        
        try:
            success = ui_bridge.launch_tui_with_session()
            
            if success:
                console.print("[green]TUI launched successfully in new window[/green]")
            else:
                console.print("[red]Failed to launch TUI[/red]")
        
        except Exception as e:
            console.print(f"[red]Error launching TUI: {e}[/red]")

    def cmd_webui(self, args: list[str]):
        """Launch Web UI interface."""
        port = 8000
        
        if args:
            try:
                port = int(args[0])
            except ValueError:
                console.print("[red]Port must be a number[/red]")
                return
        
        console.print(f"[cyan]Launching Web UI on port {port}...[/cyan]")
        
        try:
            success = ui_bridge.launch_webui(port)
            
            if success:
                console.print(f"[green]Web UI launched at http://127.0.0.1:{port}[/green]")
                console.print("[dim]Browser should open automatically[/dim]")
            else:
                console.print("[red]Failed to launch Web UI[/red]")
        
        except Exception as e:
            console.print(f"[red]Error launching Web UI: {e}[/red]")

    def cmd_sessions(self, args: list[str]):
        """List active shell sessions."""
        show_all = args and args[0] == '-a'
        show_debug = args and args[0] == '-d'
        
        all_sessions = session_manager.list_sessions()
        sessions_dict = session_manager.list_active_sessions() if not show_all and not show_debug else all_sessions
        
        if not all_sessions:
            console.print("[yellow]No sessions registered[/yellow]")
            console.print("[dim]Sessions will appear here after exploits spawn shells[/dim]")
            return
        
        if not sessions_dict:
            console.print(f"[yellow]No active sessions ({len(all_sessions)} total registered)[/yellow]")
            console.print("[dim]Use 'sessions -a' to show all registered sessions[/dim]\n")
            sessions_dict = all_sessions
        
        active_count = len(session_manager.list_active_sessions())
        console.print(f"[dim]Total: {len(all_sessions)} | Active: {active_count} | Showing: {len(sessions_dict)}[/dim]")
        
        if show_debug:
            console.print(f"[dim]Session timeout: {session_manager.session_timeout}s[/dim]\n")
        
        title = "Debug Sessions" if show_debug else ("All Sessions" if show_all else "Active Sessions")
        table = Table(title=title, show_header=True, header_style="bold cyan")
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Host", style="white", width=15)
        table.add_column("Port", style="white", width=6)
        table.add_column("Type", style="green", width=10)
        table.add_column("User@Host", style="yellow", width=20)
        table.add_column("Status", style="white", width=14)
        table.add_column("Uptime", style="dim", width=10)
        
        if show_debug:
            table.add_column("Last Seen", style="dim", width=12)
        
        for session_id, session in sessions_dict.items():
            import datetime
            alive_check = session.is_alive(session_manager.session_timeout)
            alive = "✓" if alive_check else "✗"
            status_display = f"{alive} {session.status.value}"
            
            row_data = [
                session.session_id,
                session.remote_host,
                str(session.remote_port),
                session.shell_type.value,
                f"{session.username or '?'}@{session.hostname or '?'}",
                status_display,
                session.get_uptime()
            ]
            
            if show_debug:
                last_seen = datetime.datetime.fromtimestamp(session.last_heartbeat).strftime("%H:%M:%S")
                row_data.append(last_seen)
            
            table.add_row(*row_data)
        
        console.print(table)
        
        if show_all or show_debug:
            console.print("\n[dim]Flags: -a (all sessions) | -d (debug info)[/dim]")

    def _get_operator_script_names(self, category: str) -> list[str]:
        """Get list of operator script names for a category."""
        if category not in OPERATOR_SCRIPTS:
            return []
        
        module = OPERATOR_SCRIPTS[category]
        return getattr(module, '__all__', [])

    def _get_operator_script_class(self, category: str, script_name: str):
        """Get operator script class by category and name."""
        if category not in OPERATOR_SCRIPTS:
            return None
        
        module = OPERATOR_SCRIPTS[category]
        return getattr(module, script_name, None)

    def _list_operator_scripts(self, category: str):
        """List all operator scripts in a category."""
        script_names = self._get_operator_script_names(category)
        
        if not script_names:
            console.print(f"[yellow]No scripts found in category: {category}[/yellow]")
            return
        
        table = Table(title=f"{category.title()} Operator Scripts", show_header=True, header_style="bold cyan")
        table.add_column("Script Name", style="cyan", width=30)
        table.add_column("Description", style="white", width=50)
        
        for script_name in script_names:
            script_class = self._get_operator_script_class(category, script_name)
            if script_class:
                try:
                    instance = script_class()
                    desc = getattr(instance, 'description', 'No description')
                except:
                    desc = 'No description'
            else:
                desc = 'Unknown'
            
            table.add_row(script_name, desc)
        
        console.print(table)
        console.print(f"\n[dim]Usage: {category} <script_name>[/dim]")

    def _run_operator_script(self, category: str, script_name: str):
        """Run an operator script."""
        try:
            sessions_list = shared_state.list_sessions()
            
            if not sessions_list:
                console.print("[red]No active shell sessions found[/red]")
                console.print("[yellow]Operator scripts require an active shell session[/yellow]")
                console.print("[yellow]Use TUI (command: 'tui') to spawn shells and run operator scripts[/yellow]")
                return
            
            active_session = sessions_list[0]
            
            if len(sessions_list) > 1:
                console.print(f"[yellow]Multiple sessions found, using session {active_session.session_id}[/yellow]")
        
        except Exception as e:
            console.print(f"[red]Error getting sessions: {e}[/red]")
            console.print("[yellow]Use TUI (command: 'tui') to spawn shells and run operator scripts[/yellow]")
            return
        
        script_class = self._get_operator_script_class(category, script_name)
        
        if not script_class:
            console.print(f"[red]Script not found: {script_name}[/red]")
            console.print(f"[yellow]Use '{category}' to list available scripts[/yellow]")
            return
        
        try:
            script_instance = script_class()
            console.print(f"[bold cyan][+] Running: {script_instance.name}[/bold cyan]")
            console.print(f"[dim]{script_instance.description}[/dim]")
            console.print(f"[dim]Session: {active_session.session_id} ({active_session.remote_host}:{active_session.remote_port})[/dim]\n")
            
            def mock_send_command(cmd, **kwargs):
                console.print(f"[dim]$ {cmd}[/dim]")
            
            def mock_output(msg):
                console.print(msg)
            
            result = script_instance.run(
                active_session,
                mock_send_command,
                mock_output
            )
            
            if result.success:
                console.print(f"\n[green][+] Script completed successfully[/green]")
                if result.loot:
                    console.print(f"[green][+] Loot collected: {len(result.loot)} items[/green]")
                    self.loot_manager.add_loot(script_instance.name, result.loot)
            else:
                console.print(f"\n[red][!] Script failed[/red]")
                if result.error:
                    console.print(f"[red][!] Error: {result.error}[/red]")
        
        except Exception as e:
            console.print(f"[red]Error executing script: {e}[/red]")

    def cmd_operator_script(self, category: str, args: list[str]):
        """Generic operator script command handler."""
        if not args:
            self._list_operator_scripts(category)
        else:
            script_name = args[0]
            self._run_operator_script(category, script_name)

    def process_command(self, line: str):
        """Process a console command."""
        line = line.strip()
        if not line:
            return True

        if self.recording and not line.startswith('record'):
            self.macro_commands.append(line)

        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        commands = {
            'help': self.cmd_help,
            'use': self.cmd_use,
            'set': self.cmd_set,
            'unset': self.cmd_unset,
            'show': self.cmd_show,
            'connect': self.cmd_connect,
            'disconnect': self.cmd_disconnect,
            'enumerate': self.cmd_enumerate,
            'run': self.cmd_run,
            'exploit': self.cmd_run,
            'background': self.cmd_background,
            'jobs': self.cmd_jobs,
            'kill': self.cmd_kill,
            'search': self.cmd_search,
            'record': self.cmd_record,
            'clear': self.cmd_clear,
            'listener': self.cmd_listener,
            'shell': self.cmd_shell,
            'interact': self.cmd_interact,
            'sessions': self.cmd_sessions,
            'tui': self.cmd_tui,
            'webui': self.cmd_webui,
            'escalate': lambda args: self.cmd_operator_script('escalate', args),
            'harvest': lambda args: self.cmd_operator_script('harvest', args),
            'lateral': lambda args: self.cmd_operator_script('lateral', args),
            'persist': lambda args: self.cmd_operator_script('persist', args),
            'situational': lambda args: self.cmd_operator_script('situational', args),
            'exfiltrate': lambda args: self.cmd_operator_script('exfiltrate', args),
            'utility': lambda args: self.cmd_operator_script('utility', args),
            'loot': lambda args: self.loot_manager.browse(),
            'exit': lambda args: False,
            'quit': lambda args: False,
        }

        if cmd in commands:
            result = commands[cmd](args)
            return result if result is not None else True
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")
            console.print("[yellow]Type 'help' for available commands[/yellow]")
            return True

    def run(self):
        """Start the interactive console."""
        self.print_banner()

        session = PromptSession(
            history=FileHistory(str(self.history_file)),
            completer=JenkinsConsoleCompleter(self),
            style=self.style,
            enable_history_search=True,
        )

        try:
            while True:
                try:
                    line = session.prompt(self.get_prompt())

                    if not self.process_command(line):
                        break

                except KeyboardInterrupt:
                    continue
                except EOFError:
                    break

        finally:
            if self.session:
                self.session.close()

            console.print("\n[cyan]Exiting JenkinsBreaker console[/cyan]")


def main():
    """Entry point for interactive console."""
    console_instance = JenkinsConsole()
    console_instance.run()


if __name__ == "__main__":
    main()
