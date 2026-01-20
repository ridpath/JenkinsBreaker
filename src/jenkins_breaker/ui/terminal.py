"""
Web terminal emulation with xterm.js integration and PTY bridging.
Provides interactive terminal access for post-exploitation activities.
"""

import asyncio
import os
import queue
import subprocess
import sys
import threading
import uuid
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect


class PTYSession:
    """
    Pseudo-terminal session for command execution.
    Bridges between WebSocket and subprocess for interactive shell access.
    """

    def __init__(self, session_id: str, shell: str = None):
        self.session_id = session_id
        self.shell = shell or self._detect_shell()
        self.process: Optional[subprocess.Popen] = None
        self.running = False
        self.output_queue: queue.Queue = queue.Queue()
        self.reader_thread: Optional[threading.Thread] = None

    def _detect_shell(self) -> str:
        """Detect appropriate shell for the platform."""
        if sys.platform == "win32":
            return os.environ.get("COMSPEC", "cmd.exe")
        else:
            return os.environ.get("SHELL", "/bin/bash")

    def start(self) -> bool:
        """
        Start the PTY session.

        Returns:
            True if started successfully
        """
        try:
            if sys.platform == "win32":
                self.process = subprocess.Popen(
                    self.shell,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=0,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                import fcntl
                import pty

                master, slave = pty.openpty()

                self.process = subprocess.Popen(
                    self.shell,
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    preexec_fn=os.setsid,
                    start_new_session=True
                )

                os.close(slave)

                flags = fcntl.fcntl(master, fcntl.F_GETFL)
                fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

                self.master_fd = master

            self.running = True
            self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self.reader_thread.start()

            return True

        except Exception as e:
            print(f"Failed to start PTY session: {e}")
            return False

    def _read_output(self):
        """Read output from the process and queue it."""
        while self.running:
            try:
                if sys.platform == "win32":
                    if self.process and self.process.stdout:
                        line = self.process.stdout.read(1)
                        if line:
                            self.output_queue.put(line)
                else:
                    import select

                    ready, _, _ = select.select([self.master_fd], [], [], 0.1)
                    if ready:
                        try:
                            data = os.read(self.master_fd, 1024)
                            if data:
                                self.output_queue.put(data.decode('utf-8', errors='ignore'))
                        except OSError:
                            continue
            except Exception as e:
                if self.running:
                    print(f"PTY read error: {e}")
                break

    def write(self, data: str):
        """
        Write data to the PTY.

        Args:
            data: Data to write
        """
        try:
            if sys.platform == "win32":
                if self.process and self.process.stdin:
                    self.process.stdin.write(data)
                    self.process.stdin.flush()
            else:
                os.write(self.master_fd, data.encode('utf-8'))
        except Exception as e:
            print(f"PTY write error: {e}")

    def read(self, timeout: float = 0.1) -> Optional[str]:
        """
        Read available output from the PTY.

        Args:
            timeout: Read timeout in seconds

        Returns:
            Output data or None
        """
        try:
            return self.output_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def resize(self, rows: int, cols: int):
        """
        Resize the PTY.

        Args:
            rows: Number of rows
            cols: Number of columns
        """
        if sys.platform != "win32":
            try:
                import fcntl
                import struct
                import termios

                size = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, size)
            except Exception as e:
                print(f"PTY resize error: {e}")

    def close(self):
        """Close the PTY session."""
        self.running = False

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

        if hasattr(self, 'master_fd'):
            try:
                os.close(self.master_fd)
            except Exception:
                pass

    def is_alive(self) -> bool:
        """Check if the PTY session is still alive."""
        if not self.process:
            return False
        return self.process.poll() is None


class TerminalManager:
    """
    Manages multiple terminal sessions with WebSocket connections.
    """

    def __init__(self):
        self.sessions: dict[str, PTYSession] = {}
        self.websockets: dict[str, WebSocket] = {}

    async def create_session(self, websocket: WebSocket, shell: Optional[str] = None) -> str:
        """
        Create a new terminal session.

        Args:
            websocket: WebSocket connection
            shell: Optional shell command

        Returns:
            Session ID
        """
        session_id = str(uuid.uuid4())

        pty_session = PTYSession(session_id, shell)

        if not pty_session.start():
            raise RuntimeError("Failed to start PTY session")

        self.sessions[session_id] = pty_session
        self.websockets[session_id] = websocket

        asyncio.create_task(self._stream_output(session_id))

        return session_id

    async def _stream_output(self, session_id: str):
        """Stream PTY output to WebSocket."""
        pty_session = self.sessions.get(session_id)
        websocket = self.websockets.get(session_id)

        if not pty_session or not websocket:
            return

        while pty_session.is_alive() and session_id in self.sessions:
            output = pty_session.read(timeout=0.1)

            if output:
                try:
                    await websocket.send_json({
                        "type": "output",
                        "data": output
                    })
                except Exception:
                    break

            await asyncio.sleep(0.01)

        try:
            await websocket.send_json({
                "type": "exit",
                "message": "Session terminated"
            })
        except Exception:
            pass

        self.close_session(session_id)

    async def handle_input(self, session_id: str, data: str):
        """
        Handle input from WebSocket.

        Args:
            session_id: Session identifier
            data: Input data
        """
        pty_session = self.sessions.get(session_id)

        if pty_session:
            pty_session.write(data)

    async def resize_terminal(self, session_id: str, rows: int, cols: int):
        """
        Resize a terminal session.

        Args:
            session_id: Session identifier
            rows: Number of rows
            cols: Number of columns
        """
        pty_session = self.sessions.get(session_id)

        if pty_session:
            pty_session.resize(rows, cols)

    def close_session(self, session_id: str):
        """
        Close a terminal session.

        Args:
            session_id: Session identifier
        """
        if session_id in self.sessions:
            self.sessions[session_id].close()
            del self.sessions[session_id]

        if session_id in self.websockets:
            del self.websockets[session_id]

    def close_all(self):
        """Close all terminal sessions."""
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)

    def get_session(self, session_id: str) -> Optional[PTYSession]:
        """Get a terminal session by ID."""
        return self.sessions.get(session_id)

    def list_sessions(self) -> dict[str, dict[str, any]]:
        """List all active terminal sessions."""
        return {
            session_id: {
                "shell": session.shell,
                "alive": session.is_alive()
            }
            for session_id, session in self.sessions.items()
        }


async def terminal_websocket_handler(
    websocket: WebSocket,
    terminal_manager: TerminalManager,
    shell: Optional[str] = None
):
    """
    WebSocket handler for terminal connections.

    Args:
        websocket: WebSocket connection
        terminal_manager: TerminalManager instance
        shell: Optional shell command
    """
    await websocket.accept()

    try:
        session_id = await terminal_manager.create_session(websocket, shell)

        await websocket.send_json({
            "type": "ready",
            "session_id": session_id
        })

        while True:
            message = await websocket.receive_json()

            msg_type = message.get("type")

            if msg_type == "input":
                data = message.get("data", "")
                await terminal_manager.handle_input(session_id, data)

            elif msg_type == "resize":
                rows = message.get("rows", 24)
                cols = message.get("cols", 80)
                await terminal_manager.resize_terminal(session_id, rows, cols)

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            elif msg_type == "close":
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"Terminal WebSocket error: {e}")
    finally:
        if 'session_id' in locals():
            terminal_manager.close_session(session_id)


def generate_terminal_html(websocket_url: str = "ws://localhost:8443/terminal") -> str:
    """
    Generate HTML page with xterm.js terminal.

    Args:
        websocket_url: WebSocket URL for terminal connection

    Returns:
        HTML content
    """
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>JenkinsBreaker Terminal</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.9.0/lib/xterm-addon-web-links.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Courier New', monospace;
            background: #000;
            overflow: hidden;
        }}

        #header {{
            background: #1a1a1a;
            padding: 10px 20px;
            border-bottom: 2px solid #00ff41;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        h1 {{
            color: #00ff41;
            font-size: 18px;
            margin: 0;
        }}

        #status {{
            color: #00ff41;
            font-size: 14px;
        }}

        #status.disconnected {{
            color: #ff4444;
        }}

        #terminal-container {{
            width: 100%;
            height: calc(100vh - 50px);
            padding: 10px;
        }}

        #terminal {{
            width: 100%;
            height: 100%;
        }}

        .controls {{
            display: flex;
            gap: 10px;
        }}

        button {{
            background: #00ff41;
            color: #000;
            border: none;
            padding: 5px 15px;
            cursor: pointer;
            font-weight: 600;
            border-radius: 3px;
        }}

        button:hover {{
            background: #00cc33;
        }}

        button.danger {{
            background: #ff4444;
            color: #fff;
        }}

        button.danger:hover {{
            background: #cc0000;
        }}
    </style>
</head>
<body>
    <div id="header">
        <h1>JenkinsBreaker Terminal</h1>
        <div class="controls">
            <span id="status">Connecting...</span>
            <button onclick="reconnect()">Reconnect</button>
            <button class="danger" onclick="clearTerminal()">Clear</button>
        </div>
    </div>

    <div id="terminal-container">
        <div id="terminal"></div>
    </div>

    <script>
        const term = new Terminal({{
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Courier New, monospace',
            theme: {{
                background: '#000000',
                foreground: '#00ff41',
                cursor: '#00ff41',
                black: '#000000',
                red: '#ff4444',
                green: '#00ff41',
                yellow: '#ffaa00',
                blue: '#0088ff',
                magenta: '#ff00ff',
                cyan: '#00ffff',
                white: '#ffffff',
                brightBlack: '#666666',
                brightRed: '#ff6666',
                brightGreen: '#66ff66',
                brightYellow: '#ffff66',
                brightBlue: '#6666ff',
                brightMagenta: '#ff66ff',
                brightCyan: '#66ffff',
                brightWhite: '#ffffff'
            }}
        }});

        const fitAddon = new FitAddon.FitAddon();
        const webLinksAddon = new WebLinksAddon.WebLinksAddon();

        term.loadAddon(fitAddon);
        term.loadAddon(webLinksAddon);

        term.open(document.getElementById('terminal'));
        fitAddon.fit();

        let ws = null;
        let sessionId = null;

        function connect() {{
            ws = new WebSocket('{websocket_url}');

            ws.onopen = () => {{
                updateStatus('Connected', true);
                term.clear();
                term.writeln('\\x1b[1;32mConnected to JenkinsBreaker Terminal\\x1b[0m');
                term.writeln('');
            }};

            ws.onmessage = (event) => {{
                const message = JSON.parse(event.data);

                if (message.type === 'ready') {{
                    sessionId = message.session_id;

                    const {{ rows, cols }} = term;
                    ws.send(JSON.stringify({{
                        type: 'resize',
                        rows: rows,
                        cols: cols
                    }}));
                }}

                else if (message.type === 'output') {{
                    term.write(message.data);
                }}

                else if (message.type === 'exit') {{
                    term.writeln('\\r\\n\\x1b[1;31mSession terminated\\x1b[0m');
                    updateStatus('Disconnected', false);
                }}
            }};

            ws.onclose = () => {{
                updateStatus('Disconnected', false);
                term.writeln('\\r\\n\\x1b[1;31mConnection closed\\x1b[0m');
            }};

            ws.onerror = (error) => {{
                console.error('WebSocket error:', error);
                updateStatus('Error', false);
            }};
        }}

        term.onData((data) => {{
            if (ws && ws.readyState === WebSocket.OPEN) {{
                ws.send(JSON.stringify({{
                    type: 'input',
                    data: data
                }}));
            }}
        }});

        term.onResize(({{ rows, cols }}) => {{
            if (ws && ws.readyState === WebSocket.OPEN) {{
                ws.send(JSON.stringify({{
                    type: 'resize',
                    rows: rows,
                    cols: cols
                }}));
            }}
        }});

        window.addEventListener('resize', () => {{
            fitAddon.fit();
        }});

        function updateStatus(text, connected) {{
            const status = document.getElementById('status');
            status.textContent = text;
            status.className = connected ? '' : 'disconnected';
        }}

        function reconnect() {{
            if (ws) {{
                ws.close();
            }}
            connect();
        }}

        function clearTerminal() {{
            term.clear();
        }}

        connect();

        setInterval(() => {{
            if (ws && ws.readyState === WebSocket.OPEN) {{
                ws.send(JSON.stringify({{ type: 'ping' }}));
            }}
        }}, 30000);
    </script>
</body>
</html>"""

    return html


class RemoteShellSession:
    """
    Remote shell session for post-exploitation access to compromised Jenkins servers.
    """

    def __init__(self, session_id: str, jenkins_url: str):
        self.session_id = session_id
        self.jenkins_url = jenkins_url
        self.command_history: list = []
        self.output_buffer: str = ""

    async def execute_command(self, command: str) -> str:
        """
        Execute a command on the remote Jenkins server.

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        self.command_history.append({
            "command": command,
            "timestamp": asyncio.get_event_loop().time()
        })

        output = f"Executing: {command}\n"
        output += "Command execution not implemented (requires exploit integration)\n"

        self.output_buffer += output

        return output

    def get_history(self) -> list:
        """Get command history."""
        return self.command_history

    def clear_buffer(self):
        """Clear output buffer."""
        self.output_buffer = ""


def create_terminal_manager() -> TerminalManager:
    """
    Factory function to create a TerminalManager instance.

    Returns:
        TerminalManager instance
    """
    return TerminalManager()
