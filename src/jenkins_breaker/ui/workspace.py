"""
Workspace manager for persistence across TUI sessions.
Allows saving and loading operation state for multi-day engagements.
"""

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jenkins_breaker.post.session_manager import SessionManager
from jenkins_breaker.ui.loot import LootManager


@dataclass
class WorkspaceMetadata:
    name: str
    created_at: str
    last_accessed: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class WorkspaceManager:
    """
    Manages workspace persistence for multi-day operations.

    Features:
    - Save/load TUI state (sessions, loot, targets, history)
    - SQLite backend for durability
    - Multiple workspace support
    - Operation timeline tracking
    - Target history
    """

    def __init__(self, workspace_dir: Optional[Path] = None):
        if workspace_dir is None:
            workspace_dir = Path.home() / ".jenkins_breaker" / "workspaces"

        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        self.current_workspace: Optional[str] = None
        self.db_path: Optional[Path] = None
        self.conn: Optional[sqlite3.Connection] = None

    def create_workspace(self, name: str, description: str = "") -> bool:
        """
        Create a new workspace.

        Args:
            name: Workspace name
            description: Optional description

        Returns:
            bool: True if created successfully
        """
        workspace_path = self.workspace_dir / f"{name}.db"

        if workspace_path.exists():
            return False

        try:
            conn = sqlite3.connect(str(workspace_path))
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE sessions (
                    session_id TEXT PRIMARY KEY,
                    remote_host TEXT,
                    remote_port INTEGER,
                    local_host TEXT,
                    local_port INTEGER,
                    shell_type TEXT,
                    username TEXT,
                    hostname TEXT,
                    os_type TEXT,
                    privilege_level TEXT,
                    status TEXT,
                    created_at TEXT,
                    last_seen TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE loot (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    category TEXT,
                    username TEXT,
                    password TEXT,
                    key_data TEXT,
                    token TEXT,
                    source TEXT,
                    captured_at TEXT,
                    metadata TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE,
                    version TEXT,
                    tested_at TEXT,
                    notes TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    action TEXT,
                    target TEXT,
                    details TEXT,
                    operator TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    target TEXT,
                    timestamp TEXT,
                    status TEXT,
                    details TEXT
                )
            """)

            metadata = WorkspaceMetadata(
                name=name,
                created_at=datetime.now().isoformat(),
                last_accessed=datetime.now().isoformat(),
                description=description
            )

            cursor.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                ("workspace_info", json.dumps(metadata.to_dict()))
            )

            conn.commit()
            conn.close()

            return True

        except Exception:
            return False

    def load_workspace(self, name: str) -> bool:
        """
        Load an existing workspace.

        Args:
            name: Workspace name

        Returns:
            bool: True if loaded successfully
        """
        workspace_path = self.workspace_dir / f"{name}.db"

        if not workspace_path.exists():
            return False

        try:
            if self.conn:
                self.conn.close()

            self.conn = sqlite3.connect(str(workspace_path))
            self.db_path = workspace_path
            self.current_workspace = name

            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE metadata SET value = ? WHERE key = 'last_accessed'",
                (datetime.now().isoformat(),)
            )
            self.conn.commit()

            return True

        except Exception:
            return False

    def list_workspaces(self) -> list[WorkspaceMetadata]:
        """List all available workspaces."""
        workspaces = []

        for db_file in self.workspace_dir.glob("*.db"):
            try:
                conn = sqlite3.connect(str(db_file))
                cursor = conn.cursor()

                cursor.execute("SELECT value FROM metadata WHERE key = 'workspace_info'")
                row = cursor.fetchone()

                if row:
                    workspace_data = json.loads(row[0])
                    workspaces.append(WorkspaceMetadata(**workspace_data))

                conn.close()

            except Exception:
                continue

        return workspaces

    def save_session_state(self, session_manager: SessionManager):
        """Save all sessions to workspace."""
        if not self.conn:
            return

        cursor = self.conn.cursor()

        cursor.execute("DELETE FROM sessions")

        for session_id, metadata in session_manager.list_sessions().items():
            cursor.execute("""
                INSERT INTO sessions (
                    session_id, remote_host, remote_port, local_host, local_port,
                    shell_type, username, hostname, os_type, privilege_level,
                    status, created_at, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                metadata.remote_host,
                metadata.remote_port,
                metadata.local_host,
                metadata.local_port,
                metadata.shell_type.value if metadata.shell_type else None,
                metadata.username,
                metadata.hostname,
                metadata.os_type,
                metadata.privilege_level,
                metadata.status.value,
                metadata.created_at.isoformat(),
                metadata.last_seen.isoformat()
            ))

        self.conn.commit()

    def save_loot_state(self, loot_manager: LootManager):
        """Save all loot to workspace."""
        if not self.conn:
            return

        cursor = self.conn.cursor()

        cursor.execute("DELETE FROM loot")

        for cred in loot_manager.get_all_credentials():
            cursor.execute("""
                INSERT INTO loot (
                    type, category, username, password, key_data, token,
                    source, captured_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                'credential',
                cred.type,
                cred.username,
                cred.password,
                cred.key,
                cred.token,
                cred.source,
                cred.captured_at,
                json.dumps(cred.metadata)
            ))

        for artifact in loot_manager.get_all_artifacts():
            cursor.execute("""
                INSERT INTO loot (
                    type, category, username, password, key_data, token,
                    source, captured_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                'artifact',
                artifact.type,
                artifact.name,
                artifact.content[:1000],
                artifact.path,
                None,
                artifact.source,
                artifact.captured_at,
                json.dumps(artifact.metadata)
            ))

        self.conn.commit()

    def add_target(self, url: str, version: str = "", notes: str = ""):
        """Add a tested target to workspace history."""
        if not self.conn:
            return

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO targets (url, version, tested_at, notes)
                VALUES (?, ?, ?, ?)
            """, (url, version, datetime.now().isoformat(), notes))

            self.conn.commit()
        except sqlite3.IntegrityError:
            cursor.execute("""
                UPDATE targets
                SET version = ?, tested_at = ?, notes = ?
                WHERE url = ?
            """, (version, datetime.now().isoformat(), notes, url))

            self.conn.commit()

    def add_timeline_event(
        self,
        action: str,
        target: str = "",
        details: str = "",
        operator: str = "anonymous"
    ):
        """Add an event to the operation timeline."""
        if not self.conn:
            return

        cursor = self.conn.cursor()

        cursor.execute("""
            INSERT INTO timeline (timestamp, action, target, details, operator)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), action, target, details, operator))

        self.conn.commit()

    def log_exploit_attempt(
        self,
        cve_id: str,
        target: str,
        status: str,
        details: str = ""
    ):
        """Log an exploit attempt."""
        if not self.conn:
            return

        cursor = self.conn.cursor()

        cursor.execute("""
            INSERT INTO exploits (cve_id, target, timestamp, status, details)
            VALUES (?, ?, ?, ?, ?)
        """, (cve_id, target, datetime.now().isoformat(), status, details))

        self.conn.commit()

    def get_timeline(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get operation timeline."""
        if not self.conn:
            return []

        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT timestamp, action, target, details, operator
            FROM timeline
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

        events = []
        for row in cursor.fetchall():
            events.append({
                'timestamp': row[0],
                'action': row[1],
                'target': row[2],
                'details': row[3],
                'operator': row[4]
            })

        return events

    def get_targets(self) -> list[dict[str, Any]]:
        """Get all tested targets."""
        if not self.conn:
            return []

        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT url, version, tested_at, notes
            FROM targets
            ORDER BY tested_at DESC
        """)

        targets = []
        for row in cursor.fetchall():
            targets.append({
                'url': row[0],
                'version': row[1],
                'tested_at': row[2],
                'notes': row[3]
            })

        return targets

    def get_exploit_history(self, target: Optional[str] = None) -> list[dict[str, Any]]:
        """Get exploit attempt history."""
        if not self.conn:
            return []

        cursor = self.conn.cursor()

        if target:
            cursor.execute("""
                SELECT cve_id, target, timestamp, status, details
                FROM exploits
                WHERE target = ?
                ORDER BY timestamp DESC
            """, (target,))
        else:
            cursor.execute("""
                SELECT cve_id, target, timestamp, status, details
                FROM exploits
                ORDER BY timestamp DESC
            """)

        history = []
        for row in cursor.fetchall():
            history.append({
                'cve_id': row[0],
                'target': row[1],
                'timestamp': row[2],
                'status': row[3],
                'details': row[4]
            })

        return history

    def export_workspace(self, export_path: Path) -> bool:
        """Export workspace to JSON."""
        if not self.conn:
            return False

        try:
            data = {
                'workspace': self.current_workspace,
                'exported_at': datetime.now().isoformat(),
                'timeline': self.get_timeline(limit=1000),
                'targets': self.get_targets(),
                'exploit_history': self.get_exploit_history()
            }

            with open(export_path, 'w') as f:
                json.dump(data, f, indent=2)

            return True

        except Exception:
            return False

    def close(self):
        """Close workspace connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.current_workspace = None


workspace_manager = WorkspaceManager()
