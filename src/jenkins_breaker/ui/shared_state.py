"""
Shared state manager for unified state across TUI, Web UI, and Console.
Provides centralized session tracking, loot management, and event broadcasting.
"""

import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from jenkins_breaker.post.session_manager import SessionManager, SessionMetadata
from jenkins_breaker.ui.loot import Artifact, Credential, LootManager


@dataclass
class SharedSessionInfo:
    """Unified session information visible across all UIs."""
    
    session_id: str
    session_type: str
    remote_host: str
    remote_port: int
    local_host: str
    local_port: int
    username: Optional[str] = None
    hostname: Optional[str] = None
    os_type: Optional[str] = None
    status: str = "active"
    created_at: str = ""
    last_seen: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_session_metadata(cls, meta: SessionMetadata) -> "SharedSessionInfo":
        """Convert SessionMetadata to SharedSessionInfo."""
        return cls(
            session_id=meta.session_id,
            session_type="reverse_shell",
            remote_host=meta.remote_host,
            remote_port=meta.remote_port,
            local_host=meta.local_host,
            local_port=meta.local_port,
            username=meta.username,
            hostname=meta.hostname,
            os_type=meta.os_type,
            status=meta.status.value,
            created_at=meta.created_at.isoformat(),
            last_seen=meta.last_seen.isoformat()
        )


class SharedStateManager:
    """
    Centralized state management for all UIs.
    
    Features:
    - Session tracking across TUI, Web UI, Console
    - Unified loot management
    - Event subscription and broadcasting
    - In-memory state with optional file-based persistence
    - Thread-safe operations
    """
    
    def __init__(
        self,
        loot_dir: Optional[Path] = None,
        state_file: Optional[Path] = None,
        use_redis: bool = False,
        redis_url: Optional[str] = None
    ):
        self.session_manager = SessionManager()
        self.loot_manager = LootManager(loot_dir)
        
        self.state_file = state_file or Path("loot/shared_state.json")
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.use_redis = use_redis
        self.redis_client = None
        
        if use_redis and redis_url:
            try:
                import redis
                self.redis_client = redis.Redis.from_url(redis_url)
            except ImportError:
                print("[!] Redis not available, falling back to in-memory storage")
        
        self._lock = threading.Lock()
        self._event_callbacks: list[Callable[[str, dict], None]] = []
        
        self.session_manager.start_cleanup_monitor()
        self._load_state()
    
    def _load_state(self):
        """Load persisted state from disk."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
            except Exception:
                pass
    
    def _save_state(self):
        """Persist state to disk."""
        try:
            state = {
                'sessions': [s.to_dict() for s in self.list_sessions()],
                'timestamp': datetime.now().isoformat()
            }
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"[!] Failed to save state: {e}")
    
    def register_session(
        self,
        session_id: str,
        metadata: dict[str, Any]
    ) -> bool:
        """
        Register a session accessible to all UIs.
        
        Args:
            session_id: Unique session identifier
            metadata: Session metadata (host, port, etc.)
        
        Returns:
            True if registered successfully
        """
        with self._lock:
            session_info = SharedSessionInfo(
                session_id=session_id,
                session_type=metadata.get('type', 'reverse_shell'),
                remote_host=metadata.get('remote_host', ''),
                remote_port=metadata.get('remote_port', 0),
                local_host=metadata.get('local_host', ''),
                local_port=metadata.get('local_port', 0),
                username=metadata.get('username'),
                hostname=metadata.get('hostname'),
                os_type=metadata.get('os_type'),
                status=metadata.get('status', 'active'),
                created_at=metadata.get('created_at', datetime.now().isoformat()),
                last_seen=datetime.now().isoformat()
            )
            
            if self.redis_client:
                try:
                    self.redis_client.hset(
                        f"session:{session_id}",
                        mapping=session_info.to_dict()
                    )
                except Exception:
                    pass
            
            self._broadcast_event('session_registered', session_info.to_dict())
            self._save_state()
            
            return True
    
    def get_session(self, session_id: str) -> Optional[SharedSessionInfo]:
        """Get session by ID."""
        with self._lock:
            if self.redis_client:
                try:
                    data = self.redis_client.hgetall(f"session:{session_id}")
                    if data:
                        return SharedSessionInfo(**{
                            k.decode(): v.decode() for k, v in data.items()
                        })
                except Exception:
                    pass
            
            meta = self.session_manager.get_session(session_id)
            if meta:
                return SharedSessionInfo.from_session_metadata(meta)
            
            return None
    
    def list_sessions(self) -> list[SharedSessionInfo]:
        """List all sessions across all UIs."""
        with self._lock:
            sessions = []
            
            for session_id, meta in self.session_manager.list_sessions().items():
                sessions.append(SharedSessionInfo.from_session_metadata(meta))
            
            return sessions
    
    def update_session(self, session_id: str, updates: dict[str, Any]):
        """Update session metadata."""
        with self._lock:
            session = self.get_session(session_id)
            if session:
                for key, value in updates.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
                
                session.last_seen = datetime.now().isoformat()
                
                if self.redis_client:
                    try:
                        self.redis_client.hset(
                            f"session:{session_id}",
                            mapping=session.to_dict()
                        )
                    except Exception:
                        pass
                
                self._broadcast_event('session_updated', session.to_dict())
                self._save_state()
    
    def remove_session(self, session_id: str):
        """Remove session from tracking."""
        with self._lock:
            self.session_manager.remove_session(session_id)
            
            if self.redis_client:
                try:
                    self.redis_client.delete(f"session:{session_id}")
                except Exception:
                    pass
            
            self._broadcast_event('session_removed', {'session_id': session_id})
            self._save_state()
    
    def add_loot(self, loot_item: dict[str, Any]):
        """
        Add loot accessible to all UIs.
        
        Args:
            loot_item: Dictionary with loot information
        """
        loot_type = loot_item.get('type', 'unknown')
        
        if loot_type == 'credential':
            self.loot_manager.add_credential(
                cred_type=loot_item.get('cred_type', 'unknown'),
                username=loot_item.get('username'),
                password=loot_item.get('password'),
                key=loot_item.get('key'),
                token=loot_item.get('token'),
                source=loot_item.get('source', ''),
                metadata=loot_item.get('metadata', {})
            )
        elif loot_type == 'artifact':
            self.loot_manager.add_artifact(
                name=loot_item.get('name', 'unnamed'),
                artifact_type=loot_item.get('artifact_type', 'unknown'),
                content=loot_item.get('content', ''),
                path=loot_item.get('path'),
                source=loot_item.get('source', ''),
                metadata=loot_item.get('metadata', {})
            )
        
        self._broadcast_event('loot_added', loot_item)
    
    def get_loot(
        self,
        loot_type: Optional[str] = None,
        source: Optional[str] = None
    ) -> dict[str, list]:
        """
        Get loot with optional filters.
        
        Args:
            loot_type: Filter by type (credential, artifact)
            source: Filter by source
        
        Returns:
            Dictionary with credentials and artifacts
        """
        result = {
            'credentials': [],
            'artifacts': []
        }
        
        if loot_type is None or loot_type == 'credential':
            creds = self.loot_manager.search_credentials(source=source)
            result['credentials'] = [c.to_dict() for c in creds]
        
        if loot_type is None or loot_type == 'artifact':
            artifacts = self.loot_manager.search_artifacts(source=source)
            result['artifacts'] = [a.to_dict() for a in artifacts]
        
        return result
    
    def subscribe_to_events(self, callback: Callable[[str, dict], None]):
        """
        Subscribe to state change events.
        
        Args:
            callback: Function to call on events (event_type, data)
        """
        with self._lock:
            self._event_callbacks.append(callback)
    
    def _broadcast_event(self, event_type: str, data: dict[str, Any]):
        """Broadcast event to all subscribers."""
        for callback in self._event_callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                print(f"[!] Event callback error: {e}")
    
    def get_stats(self) -> dict[str, Any]:
        """Get system statistics."""
        session_counts = self.session_manager.get_session_count()
        
        return {
            'sessions': session_counts,
            'loot': {
                'credentials': len(self.loot_manager.credentials),
                'artifacts': len(self.loot_manager.artifacts)
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def shutdown(self):
        """Clean shutdown of state manager."""
        self._save_state()
        self.session_manager.stop_cleanup_monitor()


shared_state = SharedStateManager()
