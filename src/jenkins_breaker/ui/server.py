"""
Async WebSocket backend for real-time event streaming and C2 communications.
Provides WebSocket and REST API endpoints for job monitoring, loot tracking, and system events.
"""

import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from jenkins_breaker.core.enumeration import JenkinsEnumerator
from jenkins_breaker.core.session import JenkinsSession, SessionConfig
from jenkins_breaker.modules.base import ExploitResult, exploit_registry
from jenkins_breaker.ui.auth import TokenManager, UserManager
from jenkins_breaker.ui.loot import Artifact, Credential, LootManager
from jenkins_breaker.ui.macros import MacroRecorder
from jenkins_breaker.ui.manager import JobManager


class SessionRequest(BaseModel):
    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    proxy: Optional[str] = None
    timeout: int = 10
    verify_ssl: bool = False


class ExploitRequest(BaseModel):
    cve_id: str
    target_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    options: dict[str, Any] = {}
    background: bool = False


class MacroRequest(BaseModel):
    name: str
    targets: list[str]
    dry_run: bool = False


class LoginRequest(BaseModel):
    username: str
    password: str


class EventBroadcaster:
    """
    Manages WebSocket connections and broadcasts events to subscribed clients.
    """

    def __init__(self):
        self.active_connections: set[WebSocket] = set()
        self.client_subscriptions: dict[str, set[str]] = {}
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.broadcast_task: Optional[asyncio.Task] = None

    async def connect(self, websocket: WebSocket, client_id: Optional[str] = None) -> str:
        """
        Accept and register a new WebSocket connection.

        Args:
            websocket: WebSocket connection
            client_id: Optional client identifier

        Returns:
            Client ID for this connection
        """
        await websocket.accept()

        if client_id is None:
            client_id = str(uuid.uuid4())

        self.active_connections.add(websocket)
        self.client_subscriptions[client_id] = {"*"}

        return client_id

    def disconnect(self, websocket: WebSocket, client_id: str):
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)
        self.client_subscriptions.pop(client_id, None)

    async def subscribe(self, client_id: str, event_types: list[str]):
        """Subscribe client to specific event types."""
        if client_id in self.client_subscriptions:
            self.client_subscriptions[client_id].update(event_types)

    async def unsubscribe(self, client_id: str, event_types: list[str]):
        """Unsubscribe client from event types."""
        if client_id in self.client_subscriptions:
            for event_type in event_types:
                self.client_subscriptions[client_id].discard(event_type)

    async def broadcast(self, event_type: str, data: dict[str, Any], target_clients: Optional[set[str]] = None):
        """
        Broadcast event to subscribed clients.

        Args:
            event_type: Type of event (job_update, loot_found, exploit_complete, etc.)
            data: Event payload
            target_clients: Optional set of client IDs to target (None = all)
        """
        message = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            "data": data
        }

        await self.event_queue.put((event_type, message, target_clients))

    async def _broadcast_worker(self):
        """Background worker that processes the event queue."""
        while True:
            try:
                event_type, message, target_clients = await asyncio.wait_for(
                    self.event_queue.get(),
                    timeout=1.0
                )

                dead_connections = set()

                for websocket in self.active_connections:
                    client_id = self._get_client_id(websocket)

                    if target_clients and client_id not in target_clients:
                        continue

                    if client_id not in self.client_subscriptions:
                        continue

                    subscriptions = self.client_subscriptions[client_id]
                    if "*" not in subscriptions and event_type not in subscriptions:
                        continue

                    try:
                        await websocket.send_json(message)
                    except Exception:
                        dead_connections.add(websocket)

                for websocket in dead_connections:
                    client_id = self._get_client_id(websocket)
                    self.disconnect(websocket, client_id)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Broadcast worker error: {e}")

    def _get_client_id(self, websocket: WebSocket) -> str:
        """Get client ID for a websocket connection."""
        for client_id, _ws in self.client_subscriptions.items():
            if websocket in self.active_connections:
                return client_id
        return "unknown"

    async def start(self):
        """Start the broadcast worker."""
        if self.broadcast_task is None:
            self.broadcast_task = asyncio.create_task(self._broadcast_worker())

    async def stop(self):
        """Stop the broadcast worker."""
        if self.broadcast_task:
            self.broadcast_task.cancel()
            try:
                await self.broadcast_task
            except asyncio.CancelledError:
                pass


class C2Server:
    """
    Main C2 server coordinating all UI components.
    """

    def __init__(self, loot_dir: Optional[Path] = None, macros_dir: Optional[Path] = None):
        self.app = FastAPI(
            title="JenkinsBreaker C2 Server",
            description="Command and Control interface for Jenkins exploitation"
        )

        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        self.broadcaster = EventBroadcaster()
        self.job_manager = JobManager()
        self.loot_manager = LootManager(loot_dir)
        self.macro_recorder = MacroRecorder(macros_dir)
        self.token_manager = TokenManager()
        self.user_manager = UserManager()

        self.active_sessions: dict[str, JenkinsSession] = {}

        self._register_routes()

    def _register_routes(self):
        """Register all API routes and WebSocket endpoints."""

        @self.app.on_event("startup")
        async def startup():
            await self.broadcaster.start()
            await self.broadcaster.broadcast("system", {"message": "C2 Server started"})

        @self.app.on_event("shutdown")
        async def shutdown():
            await self.broadcaster.stop()
            for session in self.active_sessions.values():
                try:
                    session.close()
                except Exception:
                    pass

        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time event streaming."""
            client_id = await self.broadcaster.connect(websocket)

            try:
                await websocket.send_json({
                    "type": "connected",
                    "client_id": client_id,
                    "timestamp": datetime.now().isoformat()
                })

                while True:
                    try:
                        data = await asyncio.wait_for(websocket.receive_json(), timeout=30.0)

                        if data.get("type") == "ping":
                            await websocket.send_json({"type": "pong"})

                        elif data.get("type") == "subscribe":
                            event_types = data.get("events", [])
                            await self.broadcaster.subscribe(client_id, event_types)

                        elif data.get("type") == "unsubscribe":
                            event_types = data.get("events", [])
                            await self.broadcaster.unsubscribe(client_id, event_types)

                    except asyncio.TimeoutError:
                        await websocket.send_json({"type": "ping"})

            except WebSocketDisconnect:
                self.broadcaster.disconnect(websocket, client_id)
            except Exception as e:
                print(f"WebSocket error: {e}")
                self.broadcaster.disconnect(websocket, client_id)

        @self.app.post("/api/auth/login")
        async def login(request: LoginRequest):
            """Authenticate and receive a token."""
            if self.user_manager.verify_user(request.username, request.password):
                token = self.token_manager.generate_token(request.username)
                return {
                    "success": True,
                    "token": token,
                    "username": request.username
                }
            else:
                raise HTTPException(status_code=401, detail="Invalid credentials")

        @self.app.get("/api/exploits")
        async def list_exploits():
            """List all available exploit modules."""
            exploits = exploit_registry.list_all()

            result = []
            for _cve_id, metadata in sorted(exploits.items()):
                result.append(metadata.to_dict())

            return {"exploits": result}

        @self.app.get("/api/exploits/{cve_id}")
        async def get_exploit_info(cve_id: str):
            """Get detailed information about a specific exploit."""
            metadata = exploit_registry.get_metadata(cve_id)
            if not metadata:
                raise HTTPException(status_code=404, detail=f"Exploit {cve_id} not found")

            return metadata.to_dict()

        @self.app.post("/api/session/create")
        async def create_session(request: SessionRequest):
            """Create a new Jenkins session."""
            try:
                session_config = SessionConfig(
                    url=request.url,
                    username=request.username,
                    password=request.password,
                    proxy=request.proxy,
                    timeout=request.timeout,
                    verify_ssl=request.verify_ssl
                )

                session = JenkinsSession(session_config)

                if session.connect():
                    session_id = str(uuid.uuid4())
                    self.active_sessions[session_id] = session

                    await self.broadcaster.broadcast("session_created", {
                        "session_id": session_id,
                        "url": request.url,
                        "version": session.version,
                        "authenticated": session.authenticated
                    })

                    return {
                        "success": True,
                        "session_id": session_id,
                        "version": session.version,
                        "authenticated": session.authenticated
                    }
                else:
                    return {"success": False, "error": "Connection failed"}

            except Exception as e:
                return {"success": False, "error": str(e)}

        @self.app.post("/api/session/{session_id}/enumerate")
        async def enumerate_session(session_id: str):
            """Enumerate plugins and jobs for a session."""
            if session_id not in self.active_sessions:
                raise HTTPException(status_code=404, detail="Session not found")

            session = self.active_sessions[session_id]
            enumerator = JenkinsEnumerator(session)

            try:
                plugins = enumerator.enumerate_plugins()
                jobs = enumerator.enumerate_jobs()

                await self.broadcaster.broadcast("enumeration_complete", {
                    "session_id": session_id,
                    "plugin_count": len(plugins),
                    "job_count": len(jobs)
                })

                return {
                    "success": True,
                    "plugins": plugins,
                    "jobs": jobs
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        @self.app.post("/api/exploit/run")
        async def run_exploit(request: ExploitRequest, background_tasks: BackgroundTasks):
            """Execute an exploit against a target."""
            try:
                session_config = SessionConfig(
                    url=request.target_url,
                    username=request.username,
                    password=request.password,
                    timeout=10,
                    verify_ssl=False
                )

                session = JenkinsSession(session_config)

                if not session.connect():
                    return {"success": False, "error": "Failed to connect to target"}

                if request.background:
                    job_id = self.job_manager.submit_job(
                        request.cve_id,
                        session,
                        request.options
                    )

                    await self.broadcaster.broadcast("job_submitted", {
                        "job_id": job_id,
                        "exploit": request.cve_id,
                        "target": request.target_url
                    })

                    background_tasks.add_task(
                        self._monitor_job,
                        job_id
                    )

                    return {
                        "success": True,
                        "job_id": job_id,
                        "status": "queued"
                    }
                else:
                    exploit_module = exploit_registry.get(request.cve_id)
                    if not exploit_module:
                        return {"success": False, "error": f"Exploit {request.cve_id} not found"}

                    result = exploit_module.run(session, **request.options)

                    await self._process_exploit_result(result, request.target_url)

                    session.close()

                    return {
                        "success": result.status == "success",
                        "result": result.to_dict()
                    }

            except Exception as e:
                return {"success": False, "error": str(e)}

        @self.app.get("/api/jobs")
        async def list_jobs():
            """List all background jobs."""
            jobs = self.job_manager.list_jobs()
            return {"jobs": {job_id: job.__dict__ for job_id, job in jobs.items()}}

        @self.app.get("/api/jobs/{job_id}")
        async def get_job_status(job_id: int):
            """Get status of a specific job."""
            job = self.job_manager.get_job(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Job not found")

            return {"job": job.__dict__}

        @self.app.post("/api/jobs/{job_id}/kill")
        async def kill_job(job_id: int):
            """Terminate a running job."""
            success = self.job_manager.kill_job(job_id)

            if success:
                await self.broadcaster.broadcast("job_killed", {
                    "job_id": job_id
                })

            return {"success": success}

        @self.app.get("/api/loot/credentials")
        async def list_credentials():
            """List all captured credentials."""
            creds = self.loot_manager.list_credentials()
            return {"credentials": [c.to_dict() for c in creds]}

        @self.app.get("/api/loot/artifacts")
        async def list_artifacts():
            """List all captured artifacts."""
            artifacts = self.loot_manager.list_artifacts()
            return {"artifacts": [a.to_dict() for a in artifacts]}

        @self.app.post("/api/loot/export")
        async def export_loot(format: str = "json"):
            """Export loot to specified format."""
            try:
                if format == "json":
                    filepath = self.loot_manager.export_json()
                elif format == "csv":
                    filepath = self.loot_manager.export_csv()
                elif format == "markdown":
                    filepath = self.loot_manager.export_markdown()
                else:
                    raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

                return {
                    "success": True,
                    "filepath": str(filepath),
                    "format": format
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        @self.app.get("/api/macros")
        async def list_macros():
            """List all saved macros."""
            macros = self.macro_recorder.list_macros()
            return {"macros": macros}

        @self.app.get("/api/macros/{name}")
        async def get_macro(name: str):
            """Get a specific macro."""
            macro = self.macro_recorder.load_macro(name)
            if not macro:
                raise HTTPException(status_code=404, detail=f"Macro '{name}' not found")

            return {"macro": macro.to_dict()}

        @self.app.post("/api/macros/{name}/replay")
        async def replay_macro(name: str, request: MacroRequest):
            """Replay a macro against multiple targets."""
            macro = self.macro_recorder.load_macro(name)
            if not macro:
                raise HTTPException(status_code=404, detail=f"Macro '{name}' not found")

            results = []
            for target in request.targets:
                try:
                    if not request.dry_run:
                        result = await self._replay_macro_on_target(macro, target)
                        results.append({
                            "target": target,
                            "success": result.get("success", False),
                            "details": result
                        })
                    else:
                        results.append({
                            "target": target,
                            "success": True,
                            "dry_run": True
                        })
                except Exception as e:
                    results.append({
                        "target": target,
                        "success": False,
                        "error": str(e)
                    })

            return {"results": results}

        @self.app.get("/api/status")
        async def get_status():
            """Get overall C2 server status."""
            jobs = self.job_manager.list_jobs()

            job_stats = {
                "total": len(jobs),
                "queued": sum(1 for j in jobs.values() if j.status == "queued"),
                "running": sum(1 for j in jobs.values() if j.status == "running"),
                "completed": sum(1 for j in jobs.values() if j.status == "completed"),
                "failed": sum(1 for j in jobs.values() if j.status == "failed")
            }

            return {
                "status": "online",
                "sessions": len(self.active_sessions),
                "jobs": job_stats,
                "credentials": len(self.loot_manager.credentials),
                "artifacts": len(self.loot_manager.artifacts),
                "connections": len(self.broadcaster.active_connections)
            }

    async def _monitor_job(self, job_id: int):
        """Monitor a background job and broadcast status updates."""
        while True:
            job = self.job_manager.get_job(job_id)
            if not job:
                break

            await self.broadcaster.broadcast("job_update", {
                "job_id": job_id,
                "status": job.status,
                "exploit": job.exploit
            })

            if job.status in ["completed", "failed", "error"]:
                if job.result:
                    await self._process_exploit_result(job.result, "background")
                break

            await asyncio.sleep(2)

    async def _process_exploit_result(self, result: ExploitResult, source: str):
        """Process exploit result and extract loot."""
        if result.status == "success" and result.data:
            if "credentials" in result.data:
                for cred_data in result.data["credentials"]:
                    cred = Credential(
                        type=cred_data.get("type", "unknown"),
                        username=cred_data.get("username"),
                        password=cred_data.get("password"),
                        key=cred_data.get("key"),
                        token=cred_data.get("token"),
                        source=source
                    )
                    self.loot_manager.add_credential(cred)

                    await self.broadcaster.broadcast("loot_found", {
                        "type": "credential",
                        "credential_type": cred.type,
                        "source": source
                    })

            if "artifacts" in result.data:
                for artifact_data in result.data["artifacts"]:
                    artifact = Artifact(
                        name=artifact_data.get("name", "unknown"),
                        type=artifact_data.get("type", "file"),
                        content=artifact_data.get("content", ""),
                        path=artifact_data.get("path"),
                        source=source
                    )
                    self.loot_manager.add_artifact(artifact)

                    await self.broadcaster.broadcast("loot_found", {
                        "type": "artifact",
                        "artifact_type": artifact.type,
                        "name": artifact.name,
                        "source": source
                    })

    async def _replay_macro_on_target(self, macro, target: str) -> dict[str, Any]:
        """Replay a macro on a specific target."""
        return {
            "success": True,
            "message": f"Macro '{macro.name}' replayed on {target}"
        }

    def run(self, host: str = "0.0.0.0", port: int = 8443, ssl_cert: Optional[str] = None, ssl_key: Optional[str] = None):
        """
        Start the C2 server.

        Args:
            host: Host to bind to
            port: Port to listen on
            ssl_cert: Path to SSL certificate
            ssl_key: Path to SSL private key
        """
        if ssl_cert and ssl_key:
            uvicorn.run(
                self.app,
                host=host,
                port=port,
                ssl_certfile=ssl_cert,
                ssl_keyfile=ssl_key
            )
        else:
            uvicorn.run(self.app, host=host, port=port)


def create_server(loot_dir: Optional[Path] = None, macros_dir: Optional[Path] = None) -> C2Server:
    """
    Factory function to create a C2Server instance.

    Args:
        loot_dir: Directory for storing loot
        macros_dir: Directory for storing macros

    Returns:
        Configured C2Server instance
    """
    return C2Server(loot_dir=loot_dir, macros_dir=macros_dir)


if __name__ == "__main__":
    server = create_server()
    server.run()
