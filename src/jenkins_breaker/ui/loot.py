"""
Loot manager for browsing, organizing, and exporting captured credentials and artifacts.
"""

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class Credential:
    """Represents a captured credential."""

    type: str  # aws, ssh, docker, npm, database, etc.
    username: Optional[str] = None
    password: Optional[str] = None
    key: Optional[str] = None
    token: Optional[str] = None
    source: str = ""
    captured_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def timestamp(self) -> datetime:
        """Get timestamp as datetime object."""
        return datetime.fromisoformat(self.captured_at)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class Artifact:
    """Represents a captured artifact (file, config, etc.)."""

    name: str
    type: str  # file, config, script, key, certificate
    content: str
    path: Optional[str] = None
    source: str = ""
    captured_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def timestamp(self) -> datetime:
        """Get timestamp as datetime object."""
        return datetime.fromisoformat(self.captured_at)

    @property
    def artifact_type(self) -> str:
        """Alias for type attribute."""
        return self.type

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class LootManager:
    """
    Manages captured credentials, artifacts, and sensitive data.

    Features:
    - Credential storage and categorization
    - Artifact management
    - Search and filter capabilities
    - Export to multiple formats (JSON, CSV, Markdown)
    - Deduplication
    - Unified storage across all UIs
    """

    def __init__(self, loot_dir: Optional[Path] = None):
        if loot_dir is None:
            loot_dir = Path.cwd() / 'loot'

        self.loot_dir = Path(loot_dir)
        self.loot_dir.mkdir(exist_ok=True)

        self.credentials: list[Credential] = []
        self.artifacts: list[Artifact] = []

        self.creds_file = self.loot_dir / 'credentials.json'
        self.artifacts_file = self.loot_dir / 'artifacts.json'
        self.sessions_file = self.loot_dir / 'sessions.json'

        (self.loot_dir / 'screenshots').mkdir(exist_ok=True)
        (self.loot_dir / 'dumps').mkdir(exist_ok=True)
        (self.loot_dir / 'exfiltrated').mkdir(exist_ok=True)

        self._load()

    def _load(self):
        """Load existing loot from disk."""
        if self.creds_file.exists():
            try:
                with open(self.creds_file) as f:
                    data = json.load(f)
                    self.credentials = [Credential(**c) for c in data]
            except Exception:
                pass

        if self.artifacts_file.exists():
            try:
                with open(self.artifacts_file) as f:
                    data = json.load(f)
                    self.artifacts = [Artifact(**a) for a in data]
            except Exception:
                pass

    def _save(self):
        """Save loot to disk."""
        with open(self.creds_file, 'w') as f:
            json.dump([c.to_dict() for c in self.credentials], f, indent=2)

        with open(self.artifacts_file, 'w') as f:
            json.dump([a.to_dict() for a in self.artifacts], f, indent=2)

    def add_credential(
        self,
        cred_type: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key: Optional[str] = None,
        token: Optional[str] = None,
        source: str = "",
        metadata: Optional[dict[str, Any]] = None
    ):
        """
        Add a credential to the loot.

        Args:
            cred_type: Type of credential (aws, ssh, docker, etc.)
            username: Username if applicable
            password: Password if applicable
            key: Private key if applicable
            token: Access token if applicable
            source: Where this credential was found
            metadata: Additional metadata
        """
        cred = Credential(
            type=cred_type,
            username=username,
            password=password,
            key=key,
            token=token,
            source=source,
            metadata=metadata or {}
        )

        if not self._is_duplicate_credential(cred):
            self.credentials.append(cred)
            self._save()

    def add_artifact(
        self,
        name: str,
        artifact_type: str,
        content: str,
        path: Optional[str] = None,
        source: str = "",
        metadata: Optional[dict[str, Any]] = None
    ):
        """
        Add an artifact to the loot.

        Args:
            name: Artifact name
            artifact_type: Type (file, config, script, etc.)
            content: Artifact content
            path: Original path
            source: Where this was captured
            metadata: Additional metadata
        """
        artifact = Artifact(
            name=name,
            type=artifact_type,
            content=content,
            path=path,
            source=source,
            metadata=metadata or {}
        )

        if not self._is_duplicate_artifact(artifact):
            self.artifacts.append(artifact)
            self._save()

    def add_loot(self, exploit_name: str, data: dict[str, Any]):
        """
        Add loot from an exploit result.

        Args:
            exploit_name: Name of the exploit that captured this
            data: Dictionary containing credentials and/or artifacts
        """
        if 'credentials' in data:
            for cred_data in data['credentials']:
                self.add_credential(
                    cred_type=cred_data.get('type', 'unknown'),
                    username=cred_data.get('username'),
                    password=cred_data.get('password'),
                    key=cred_data.get('key'),
                    token=cred_data.get('token'),
                    source=exploit_name,
                    metadata=cred_data.get('metadata', {})
                )

        if 'artifacts' in data:
            for artifact_data in data['artifacts']:
                self.add_artifact(
                    name=artifact_data.get('name', 'unnamed'),
                    artifact_type=artifact_data.get('type', 'unknown'),
                    content=artifact_data.get('content', ''),
                    path=artifact_data.get('path'),
                    source=exploit_name,
                    metadata=artifact_data.get('metadata', {})
                )

    def _is_duplicate_credential(self, cred: Credential) -> bool:
        """Check if credential already exists."""
        for existing in self.credentials:
            if (existing.type == cred.type and
                existing.username == cred.username and
                existing.password == cred.password and
                existing.key == cred.key and
                existing.token == cred.token):
                return True
        return False

    def _is_duplicate_artifact(self, artifact: Artifact) -> bool:
        """Check if artifact already exists."""
        for existing in self.artifacts:
            if (existing.name == artifact.name and
                existing.type == artifact.type and
                existing.content == artifact.content):
                return True
        return False

    def search_credentials(
        self,
        cred_type: Optional[str] = None,
        username: Optional[str] = None,
        source: Optional[str] = None
    ) -> list[Credential]:
        """
        Search for credentials.

        Args:
            cred_type: Filter by credential type
            username: Filter by username (partial match)
            source: Filter by source exploit

        Returns:
            List of matching credentials
        """
        results = self.credentials

        if cred_type:
            results = [c for c in results if c.type == cred_type]

        if username:
            results = [c for c in results if c.username and username.lower() in c.username.lower()]

        if source:
            results = [c for c in results if source.lower() in c.source.lower()]

        return results

    def search_artifacts(
        self,
        artifact_type: Optional[str] = None,
        name: Optional[str] = None,
        source: Optional[str] = None
    ) -> list[Artifact]:
        """
        Search for artifacts.

        Args:
            artifact_type: Filter by artifact type
            name: Filter by name (partial match)
            source: Filter by source exploit

        Returns:
            List of matching artifacts
        """
        results = self.artifacts

        if artifact_type:
            results = [a for a in results if a.type == artifact_type]

        if name:
            results = [a for a in results if name.lower() in a.name.lower()]

        if source:
            results = [a for a in results if source.lower() in a.source.lower()]

        return results

    def display_summary(self):
        """Display a summary of captured loot."""
        console.print("\n[bold cyan]Loot Summary[/bold cyan]")
        console.print(f"[white]Total Credentials:[/white] {len(self.credentials)}")
        console.print(f"[white]Total Artifacts:[/white] {len(self.artifacts)}")

        if self.credentials:
            cred_types = {}
            for cred in self.credentials:
                cred_types[cred.type] = cred_types.get(cred.type, 0) + 1

            console.print("\n[bold cyan]Credentials by Type:[/bold cyan]")
            for cred_type, count in sorted(cred_types.items()):
                console.print(f"  - {cred_type}: {count}")

    def display_credentials(self, cred_type: Optional[str] = None):
        """Display credentials in a table."""
        creds = self.search_credentials(cred_type=cred_type) if cred_type else self.credentials

        if not creds:
            console.print("[yellow]No credentials found[/yellow]")
            return

        table = Table(title=f"Credentials ({len(creds)})", show_header=True, header_style="bold cyan")
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Username", style="green", width=20)
        table.add_column("Password", style="yellow", width=20)
        table.add_column("Source", style="white", width=25)
        table.add_column("Captured", style="dim", width=20)

        for cred in creds:
            password_display = cred.password[:20] + "..." if cred.password and len(cred.password) > 20 else (cred.password or "")
            username_display = cred.username or (cred.token[:15] + "..." if cred.token else "")

            table.add_row(
                cred.type,
                username_display,
                password_display,
                cred.source,
                cred.captured_at[:10]
            )

        console.print(table)

    def display_artifacts(self, artifact_type: Optional[str] = None):
        """Display artifacts in a table."""
        artifacts = self.search_artifacts(artifact_type=artifact_type) if artifact_type else self.artifacts

        if not artifacts:
            console.print("[yellow]No artifacts found[/yellow]")
            return

        table = Table(title=f"Artifacts ({len(artifacts)})", show_header=True, header_style="bold cyan")
        table.add_column("Name", style="cyan", width=30)
        table.add_column("Type", style="green", width=15)
        table.add_column("Size", style="yellow", width=10)
        table.add_column("Source", style="white", width=25)

        for artifact in artifacts:
            size = f"{len(artifact.content)} bytes"
            table.add_row(
                artifact.name,
                artifact.type,
                size,
                artifact.source
            )

        console.print(table)

    def export_credentials_json(self, output_file: Optional[Path] = None) -> Path:
        """Export credentials to JSON."""
        if output_file is None:
            output_file = self.loot_dir / f'credentials_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

        output_file = Path(output_file)

        with open(output_file, 'w') as f:
            json.dump([c.to_dict() for c in self.credentials], f, indent=2)

        return output_file

    def export_credentials_csv(self, output_file: Optional[Path] = None) -> Path:
        """Export credentials to CSV."""
        if output_file is None:
            output_file = self.loot_dir / f'credentials_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

        output_file = Path(output_file)

        with open(output_file, 'w', newline='') as f:
            if not self.credentials:
                return output_file

            fieldnames = ['type', 'username', 'password', 'key', 'token', 'source', 'captured_at']
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            writer.writeheader()
            for cred in self.credentials:
                row = {k: v for k, v in cred.to_dict().items() if k in fieldnames}
                writer.writerow(row)

        return output_file

    def export_credentials_markdown(self, output_file: Optional[Path] = None) -> Path:
        """Export credentials to Markdown."""
        if output_file is None:
            output_file = self.loot_dir / f'credentials_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'

        output_file = Path(output_file)

        with open(output_file, 'w') as f:
            f.write("# Captured Credentials\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            if not self.credentials:
                f.write("No credentials captured.\n")
                return output_file

            cred_types = {}
            for cred in self.credentials:
                if cred.type not in cred_types:
                    cred_types[cred.type] = []
                cred_types[cred.type].append(cred)

            for cred_type, creds in sorted(cred_types.items()):
                f.write(f"## {cred_type.upper()} Credentials\n\n")
                f.write("| Username | Password | Source | Captured |\n")
                f.write("|----------|----------|--------|----------|\n")

                for cred in creds:
                    username = cred.username or (cred.token[:20] + "..." if cred.token else "N/A")
                    password = cred.password or cred.key[:20] + "..." if cred.key else "N/A"
                    f.write(f"| {username} | {password} | {cred.source} | {cred.captured_at[:10]} |\n")

                f.write("\n")

        return output_file

    def browse(self):
        """Interactive browser for loot."""
        self.display_summary()
        console.print("\n[dim]Use display_credentials() or display_artifacts() to view details[/dim]")

    def clear(self):
        """Clear all loot."""
        self.credentials = []
        self.artifacts = []
        self._save()
        console.print("[green]Loot cleared[/green]")

    def get_statistics(self) -> dict[str, Any]:
        """Get loot statistics."""
        cred_types = {}
        for cred in self.credentials:
            cred_types[cred.type] = cred_types.get(cred.type, 0) + 1

        artifact_types = {}
        for artifact in self.artifacts:
            artifact_types[artifact.type] = artifact_types.get(artifact.type, 0) + 1

        return {
            'total_credentials': len(self.credentials),
            'total_artifacts': len(self.artifacts),
            'credential_types': cred_types,
            'artifact_types': artifact_types
        }

    def get_all_credentials(self) -> list[Credential]:
        """Get all credentials."""
        return self.credentials

    def get_all_artifacts(self) -> list[Artifact]:
        """Get all artifacts."""
        return self.artifacts

    def export_metasploit_creds(self, output_file: Optional[Path] = None) -> Path:
        """
        Export credentials in Metasploit creds format.
        Compatible with: msfconsole > creds -a
        """
        if output_file is None:
            output_file = self.loot_dir / f'msf_creds_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'

        output_file = Path(output_file)

        with open(output_file, 'w') as f:
            for cred in self.credentials:
                if cred.username and cred.password:
                    f.write(f"{cred.username}:{cred.password}\n")

        return output_file

    def export_crackmapexec_format(self, output_file: Optional[Path] = None) -> Path:
        """
        Export credentials for CrackMapExec password spraying.
        Format: username:password or username:hash
        """
        if output_file is None:
            output_file = self.loot_dir / f'cme_creds_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'

        output_file = Path(output_file)

        with open(output_file, 'w') as f:
            for cred in self.credentials:
                if cred.username and cred.password:
                    f.write(f"{cred.username}:{cred.password}\n")

        return output_file

    def export_keepass_csv(self, output_file: Optional[Path] = None) -> Path:
        """
        Export credentials in KeePass CSV import format.
        Format: "Account","Login Name","Password","Web Site","Comments"
        """
        if output_file is None:
            output_file = self.loot_dir / f'keepass_import_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

        output_file = Path(output_file)

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Account", "Login Name", "Password", "Web Site", "Comments"])

            for cred in self.credentials:
                account = f"{cred.type.upper()}"
                login = cred.username or ""
                password = cred.password or cred.key or cred.token or ""
                website = ""
                comments = f"Source: {cred.source} | Captured: {cred.captured_at[:10]}"

                writer.writerow([account, login, password, website, comments])

        return output_file

    def export_1password_csv(self, output_file: Optional[Path] = None) -> Path:
        """
        Export credentials in 1Password CSV import format.
        Format: title,website,username,password,notes,type
        """
        if output_file is None:
            output_file = self.loot_dir / f'1password_import_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

        output_file = Path(output_file)

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["title", "website", "username", "password", "notes", "type"])

            for cred in self.credentials:
                title = f"{cred.type.upper()} - {cred.source}"
                website = ""
                username = cred.username or ""
                password = cred.password or cred.key or cred.token or ""
                notes = f"Captured: {cred.captured_at}\nMetadata: {json.dumps(cred.metadata)}"
                item_type = "Login"

                writer.writerow([title, website, username, password, notes, item_type])

        return output_file

    def save_session_info(self, session_id: str, session_data: dict[str, Any]):
        """
        Save session information to loot directory.
        
        Args:
            session_id: Unique session identifier
            session_data: Session metadata
        """
        try:
            sessions = []
            
            if self.sessions_file.exists():
                with open(self.sessions_file) as f:
                    sessions = json.load(f)
            
            session_data['session_id'] = session_id
            session_data['saved_at'] = datetime.now().isoformat()
            
            existing_idx = None
            for idx, s in enumerate(sessions):
                if s.get('session_id') == session_id:
                    existing_idx = idx
                    break
            
            if existing_idx is not None:
                sessions[existing_idx] = session_data
            else:
                sessions.append(session_data)
            
            with open(self.sessions_file, 'w') as f:
                json.dump(sessions, f, indent=2)
        
        except Exception as e:
            console.print(f"[red]Failed to save session info: {e}[/red]")

    def load_sessions(self) -> list[dict[str, Any]]:
        """
        Load saved session information.
        
        Returns:
            List of session metadata dictionaries
        """
        try:
            if self.sessions_file.exists():
                with open(self.sessions_file) as f:
                    return json.load(f)
        except Exception:
            pass
        
        return []

    def save_file_artifact(
        self,
        filename: str,
        content: bytes,
        category: str = 'exfiltrated',
        metadata: Optional[dict[str, Any]] = None
    ) -> Path:
        """
        Save a file artifact to the loot directory.
        
        Args:
            filename: Name of the file
            content: File content as bytes
            category: Category (screenshots, dumps, exfiltrated)
            metadata: Additional metadata
        
        Returns:
            Path to saved file
        """
        category_dir = self.loot_dir / category
        category_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{filename}"
        
        file_path = category_dir / safe_filename
        
        with open(file_path, 'wb') as f:
            f.write(content)
        
        self.add_artifact(
            name=safe_filename,
            artifact_type='file',
            content=f"File saved to: {file_path}",
            path=str(file_path),
            source=category,
            metadata=metadata or {}
        )
        
        return file_path

    def get_recent_loot(self, limit: int = 10) -> dict[str, list]:
        """
        Get recently captured loot.
        
        Args:
            limit: Maximum number of items to return
        
        Returns:
            Dictionary with recent credentials and artifacts
        """
        recent_creds = sorted(
            self.credentials,
            key=lambda c: c.captured_at,
            reverse=True
        )[:limit]
        
        recent_artifacts = sorted(
            self.artifacts,
            key=lambda a: a.captured_at,
            reverse=True
        )[:limit]
        
        return {
            'credentials': [c.to_dict() for c in recent_creds],
            'artifacts': [a.to_dict() for a in recent_artifacts]
        }


loot_manager = LootManager()
