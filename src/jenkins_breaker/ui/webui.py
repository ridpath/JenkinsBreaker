#!/usr/bin/env python3
"""
JenkinsBreaker Web UI - Browser-based interface using FastAPI
RESTful API backend with WebSocket support for real-time exploit monitoring
"""

from datetime import datetime
from typing import Optional
import tempfile
import importlib.util
import shutil
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, UploadFile, File
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from jenkins_breaker.core.enumeration import JenkinsEnumerator
from jenkins_breaker.core.fuzzer import JenkinsFuzzer
from jenkins_breaker.core.session import JenkinsSession, SessionConfig
import jenkins_breaker.modules
from jenkins_breaker.modules.base import exploit_registry
from jenkins_breaker.ui.ui_bridge import ui_bridge
from jenkins_breaker.ui.shared_state import shared_state

app = FastAPI(title="JenkinsBreaker Web UI", version="2.0.0")

sessions: dict[str, dict] = {}
active_exploits: list[dict] = []
exploit_log: list[dict] = []


class TargetConfig(BaseModel):
    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    proxy: Optional[str] = None


class ExploitRequest(BaseModel):
    cve_id: str
    target_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    parameters: Optional[dict[str, str]] = {}


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass


manager = ConnectionManager()


@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve the main UI"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>JenkinsBreaker Web UI</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a1a; color: #fff; }
            .header { background: #2d2d2d; padding: 20px; border-bottom: 2px solid #00ff41; }
            .header h1 { color: #00ff41; font-size: 28px; }
            .container { display: grid; grid-template-columns: 300px 1fr; gap: 20px; padding: 20px; height: calc(100vh - 80px); }
            .sidebar { background: #2d2d2d; padding: 20px; border-radius: 8px; overflow-y: auto; }
            .main { background: #2d2d2d; padding: 20px; border-radius: 8px; overflow-y: auto; }
            .input-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; color: #00ff41; font-size: 14px; font-weight: 600; }
            input, select { width: 100%; padding: 10px; background: #1a1a1a; border: 1px solid #444; color: #fff; border-radius: 4px; }
            input:focus, select:focus { outline: none; border-color: #00ff41; }
            .btn { padding: 12px 24px; background: #00ff41; color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; margin-right: 10px; margin-top: 10px; }
            .btn:hover { background: #00cc33; }
            .btn-danger { background: #ff4444; color: #fff; }
            .btn-danger:hover { background: #cc0000; }
            .btn-secondary { background: #666; color: #fff; }
            .btn-secondary:hover { background: #555; }
            .cve-list { margin-top: 20px; }
            .cve-item { background: #1a1a1a; padding: 12px; margin-bottom: 8px; border-radius: 4px; border-left: 3px solid #00ff41; cursor: pointer; }
            .cve-item:hover { background: #222; }
            .cve-id { color: #00ff41; font-weight: 600; margin-bottom: 4px; }
            .cve-name { color: #ccc; font-size: 13px; }
            .severity { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; margin-top: 4px; }
            .severity-critical { background: #ff0000; color: #fff; }
            .severity-high { background: #ff8800; color: #fff; }
            .severity-medium { background: #ffcc00; color: #000; }
            .severity-low { background: #00ff00; color: #000; }
            .log-container { background: #1a1a1a; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; max-height: 500px; overflow-y: auto; }
            .log-entry { padding: 4px 0; border-bottom: 1px solid #333; }
            .log-time { color: #666; margin-right: 10px; }
            .log-info { color: #00aaff; }
            .log-success { color: #00ff41; }
            .log-error { color: #ff4444; }
            .log-warning { color: #ffaa00; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
            .stat-card { background: #1a1a1a; padding: 20px; border-radius: 4px; border-left: 3px solid #00ff41; }
            .stat-value { font-size: 32px; font-weight: 700; color: #00ff41; margin-bottom: 5px; }
            .stat-label { color: #999; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>JenkinsBreaker Web UI</h1>
        </div>

        <div class="container">
            <div class="sidebar">
                <h2 style="color: #00ff41; margin-bottom: 20px;">Target Configuration</h2>

                <div class="input-group">
                    <label>Jenkins URL</label>
                    <input type="text" id="target-url" placeholder="http://jenkins.example.com:8080" value="http://localhost:8080">
                </div>

                <div class="input-group">
                    <label>Username</label>
                    <input type="text" id="username" placeholder="admin" value="admin">
                </div>

                <div class="input-group">
                    <label>Password</label>
                    <input type="password" id="password" placeholder="password" value="admin">
                </div>

                <button class="btn" onclick="connect()">Connect</button>
                <button class="btn btn-secondary" onclick="enumerate()">Enumerate</button>
                <button class="btn btn-secondary" onclick="runFuzzer()">Run Fuzzer</button>
                
                <h3 style="color: #00ff41; margin: 20px 0 10px 0;">Launch Other UIs</h3>
                <button class="btn btn-secondary" onclick="launchTUI()">Launch TUI</button>
                <button class="btn btn-secondary" onclick="launchConsole()">Launch Console</button>

                <h3 style="color: #00ff41; margin: 20px 0 10px 0;">Upload Custom Modules</h3>
                
                <div class="input-group">
                    <label>Exploit Module (.py)</label>
                    <input type="file" id="exploit-file" accept=".py" style="padding: 5px;">
                    <button class="btn btn-secondary" style="margin-top: 5px; width: 100%;" onclick="uploadExploit()">Upload Exploit</button>
                </div>
                
                <div class="input-group">
                    <label>Operator Script (.py)</label>
                    <input type="file" id="script-file" accept=".py" style="padding: 5px;">
                    <select id="script-category" style="margin-top: 5px;">
                        <option value="escalate">Escalate</option>
                        <option value="harvest">Harvest</option>
                        <option value="lateral">Lateral</option>
                        <option value="persist">Persist</option>
                        <option value="situational">Situational</option>
                        <option value="exfiltrate">Exfiltrate</option>
                        <option value="utility">Utility</option>
                    </select>
                    <button class="btn btn-secondary" style="margin-top: 5px; width: 100%;" onclick="uploadOperatorScript()">Upload Script</button>
                </div>

                <div class="cve-list">
                    <h3 style="color: #00ff41; margin-bottom: 10px;">Available Exploits</h3>
                    <div id="exploit-list"></div>
                </div>
            </div>

            <div class="main">
                <h2 style="color: #00ff41; margin-bottom: 20px;">Exploitation Dashboard</h2>

                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-value" id="stat-total">0</div>
                        <div class="stat-label">Exploits Run</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="stat-success">0</div>
                        <div class="stat-label">Successful</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="stat-failed">0</div>
                        <div class="stat-label">Failed</div>
                    </div>
                </div>

                <h3 style="color: #00ff41; margin-bottom: 10px;">Exploitation Log</h3>
                <div class="log-container" id="log-container">
                    <div class="log-entry">
                        <span class="log-time">[00:00:00]</span>
                        <span class="log-info">[INFO] JenkinsBreaker Web UI initialized</span>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let ws = null;
            let stats = { total: 0, success: 0, failed: 0 };

            async function loadExploits() {
                const response = await fetch('/api/exploits');
                const exploits = await response.json();

                const container = document.getElementById('exploit-list');
                container.innerHTML = '';

                for (const exploit of exploits) {
                    const item = document.createElement('div');
                    item.className = 'cve-item';
                    item.onclick = () => selectExploit(exploit.cve_id);

                    const severityClass = `severity-${exploit.severity.toLowerCase()}`;

                    item.innerHTML = `
                        <div class="cve-id">${exploit.cve_id}</div>
                        <div class="cve-name">${exploit.name}</div>
                        <span class="severity ${severityClass}">${exploit.severity.toUpperCase()}</span>
                    `;

                    container.appendChild(item);
                }

                addLogEntry('info', `Loaded ${exploits.length} exploit modules`);
            }

            let heartbeatInterval = null;
            
            function initWebSocket() {
                ws = new WebSocket('ws://localhost:8000/ws');

                ws.onopen = function() {
                    if (heartbeatInterval) {
                        clearInterval(heartbeatInterval);
                    }
                    heartbeatInterval = setInterval(() => {
                        if (ws && ws.readyState === WebSocket.OPEN) {
                            ws.send('ping');
                        }
                    }, 30000);
                };

                ws.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    if (data.type === 'log') {
                        addLogEntry(data.level, data.message);
                    } else if (data.type === 'stats') {
                        updateStats(data.stats);
                    }
                };

                ws.onclose = function() {
                    if (heartbeatInterval) {
                        clearInterval(heartbeatInterval);
                    }
                    setTimeout(initWebSocket, 5000);
                };

                ws.onerror = function(error) {
                    console.error('WebSocket error:', error);
                };
            }

            function addLogEntry(level, message) {
                const log = document.getElementById('log-container');
                const time = new Date().toLocaleTimeString();
                const entry = document.createElement('div');
                entry.className = 'log-entry';
                entry.innerHTML = `<span class="log-time">[${time}]</span><span class="log-${level}">[${level.toUpperCase()}] ${message}</span>`;
                log.appendChild(entry);
                log.scrollTop = log.scrollHeight;
            }

            function updateStats(newStats) {
                stats = newStats;
                document.getElementById('stat-total').textContent = stats.total;
                document.getElementById('stat-success').textContent = stats.success;
                document.getElementById('stat-failed').textContent = stats.failed;
            }

            async function connect() {
                const url = document.getElementById('target-url').value;
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;

                if (!url) {
                    addLogEntry('error', 'Please enter a target URL');
                    return;
                }

                addLogEntry('info', `Connecting to ${url}...`);

                const response = await fetch('/api/connect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, username, password })
                });

                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', `Connected to Jenkins ${data.version}`);
                } else {
                    addLogEntry('error', `Connection failed: ${data.error}`);
                }
            }

            async function enumerate() {
                const url = document.getElementById('target-url').value;
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;

                if (!url) {
                    addLogEntry('error', 'Please connect to a target first');
                    return;
                }

                addLogEntry('info', 'Enumerating plugins...');

                const response = await fetch('/api/enumerate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, username, password })
                });

                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', `Enumerated ${data.plugin_count} plugins`);
                    if (data.job_count !== undefined) {
                        addLogEntry('success', `Found ${data.job_count} jobs`);
                    }
                } else {
                    addLogEntry('error', `Enumeration failed: ${data.error}`);
                }
            }

            async function runFuzzer() {
                const url = document.getElementById('target-url').value;
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;

                if (!url) {
                    addLogEntry('error', 'Please connect to a target first');
                    return;
                }

                addLogEntry('info', 'Starting comprehensive fuzzer scan...');

                const response = await fetch('/api/fuzz', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, username, password })
                });

                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', `Fuzzer scan complete: ${data.total_findings} findings`);
                    
                    const findings = data.findings;
                    for (const [category, results] of Object.entries(findings)) {
                        if (results.length > 0) {
                            addLogEntry('info', `[${category.toUpperCase()}] ${results.length} finding(s)`);
                            results.forEach(finding => {
                                const severity = finding.severity || 'info';
                                addLogEntry(severity === 'critical' || severity === 'high' ? 'error' : 
                                          severity === 'medium' ? 'warning' : 'info',
                                          `  → ${finding.description || finding.type}`);
                            });
                        }
                    }
                } else {
                    addLogEntry('error', `Fuzzer scan failed: ${data.error}`);
                }
            }

            async function selectExploit(cveId) {
                const url = document.getElementById('target-url').value;
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;

                if (!url) {
                    addLogEntry('error', 'Please connect to a target first');
                    return;
                }

                addLogEntry('info', `Executing exploit ${cveId}...`);
                stats.total++;
                updateStats(stats);

                const response = await fetch('/api/exploit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cve_id: cveId, target_url: url, username, password })
                });

                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', `Exploit ${cveId} succeeded: ${data.details}`);
                    stats.success++;
                } else {
                    addLogEntry('error', `Exploit ${cveId} failed: ${data.error}`);
                    stats.failed++;
                }
                updateStats(stats);
            }

            async function launchTUI() {
                addLogEntry('info', 'Launching TUI...');
                
                const response = await fetch('/api/ui/launch_tui', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });

                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', 'TUI launched successfully');
                } else {
                    addLogEntry('error', `Failed to launch TUI: ${data.error}`);
                }
            }

            async function launchConsole() {
                addLogEntry('info', 'Launching Console UI...');
                
                const response = await fetch('/api/ui/launch_console', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                const data = await response.json();
                if (data.success) {
                    addLogEntry('success', 'Console UI launched successfully');
                } else {
                    addLogEntry('error', `Failed to launch Console: ${data.error}`);
                }
            }

            async function uploadExploit() {
                const fileInput = document.getElementById('exploit-file');
                const file = fileInput.files[0];
                
                if (!file) {
                    addLogEntry('error', 'Please select a file to upload');
                    return;
                }
                
                addLogEntry('info', `Uploading exploit module: ${file.name}...`);
                
                const formData = new FormData();
                formData.append('file', file);
                
                try {
                    const response = await fetch('/api/exploits/upload', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        addLogEntry('success', `Exploit ${result.cve_id} uploaded successfully!`);
                        fileInput.value = '';
                        loadExploits();
                    } else {
                        addLogEntry('error', `Upload failed: ${result.error}`);
                    }
                } catch (error) {
                    addLogEntry('error', `Upload error: ${error.message}`);
                }
            }

            async function uploadOperatorScript() {
                const fileInput = document.getElementById('script-file');
                const category = document.getElementById('script-category').value;
                const file = fileInput.files[0];
                
                if (!file) {
                    addLogEntry('error', 'Please select a file to upload');
                    return;
                }
                
                addLogEntry('info', `Uploading operator script: ${file.name} to ${category} category...`);
                
                const formData = new FormData();
                formData.append('file', file);
                formData.append('category', category);
                
                try {
                    const response = await fetch(`/api/operator_scripts/upload?category=${category}`, {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        addLogEntry('success', `Script '${result.name}' uploaded to ${result.category} successfully!`);
                        fileInput.value = '';
                    } else {
                        addLogEntry('error', `Upload failed: ${result.error}`);
                    }
                } catch (error) {
                    addLogEntry('error', `Upload error: ${error.message}`);
                }
            }

            loadExploits();
            initWebSocket();
        </script>
    </body>
    </html>
    """


@app.get("/api/exploits")
async def list_exploits():
    """List available exploit modules"""
    exploits = exploit_registry.list_all()

    result = []
    for cve_id, metadata in sorted(exploits.items()):
        result.append({
            "cve_id": cve_id,
            "name": metadata.name,
            "description": metadata.description,
            "severity": metadata.severity,
            "requires_auth": metadata.requires_auth,
            "mitre_attack": metadata.mitre_attack,
        })

    return result


@app.post("/api/connect")
async def connect_target(config: TargetConfig):
    """Connect to Jenkins target"""
    try:
        session_config = SessionConfig(
            url=config.url,
            username=config.username,
            password=config.password,
            timeout=10,
            verify_ssl=False
        )

        session = JenkinsSession(session_config)

        if session.connect():
            version = session.version or "Unknown"

            session_id = datetime.now().isoformat()
            sessions[session_id] = {
                "url": config.url,
                "username": config.username,
                "version": version,
                "connected_at": datetime.now().isoformat()
            }

            await manager.broadcast({
                "type": "log",
                "level": "success",
                "message": f"Connected to Jenkins {version}"
            })

            session.close()

            return {"success": True, "version": version, "session_id": session_id}
        else:
            return {"success": False, "error": "Connection failed"}

    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/fuzz")
async def fuzz_target(config: TargetConfig):
    """Run comprehensive fuzzer scan against Jenkins target"""
    try:
        session_config = SessionConfig(
            url=config.url,
            username=config.username,
            password=config.password,
            timeout=10,
            verify_ssl=False
        )

        session = JenkinsSession(session_config)

        if not session.connect():
            return {"success": False, "error": "Failed to connect"}

        fuzzer = JenkinsFuzzer(
            base_url=session.base_url,
            username=config.username,
            password=config.password,
            session=session.session
        )

        await manager.broadcast({
            "type": "log",
            "level": "info",
            "message": "Running comprehensive fuzzer scan..."
        })

        findings = fuzzer.fuzz_all()
        total_findings = sum(len(f) for f in findings.values())

        session.close()

        await manager.broadcast({
            "type": "log",
            "level": "success",
            "message": f"Fuzzer scan complete: {total_findings} findings"
        })

        for category, results in findings.items():
            if results:
                await manager.broadcast({
                    "type": "log",
                    "level": "info",
                    "message": f"[{category.upper()}] {len(results)} finding(s)"
                })

        return {
            "success": True,
            "total_findings": total_findings,
            "findings": findings
        }

    except Exception as e:
        return {"success": False, "error": str(e), "total_findings": 0, "findings": {}}


@app.post("/api/enumerate")
async def enumerate_target(config: TargetConfig):
    """Enumerate Jenkins plugins"""
    try:
        session_config = SessionConfig(
            url=config.url,
            username=config.username,
            password=config.password,
            timeout=10,
            verify_ssl=False
        )

        session = JenkinsSession(session_config)

        if not session.connect():
            return {"success": False, "error": "Failed to connect"}

        enumerator = JenkinsEnumerator(
            base_url=session.base_url,
            auth=session.auth,
            proxies={},
            verify_ssl=False,
            timeout=10,
            delay=0.0
        )

        result = enumerator.enumerate_all()

        plugin_count = len(result.plugins) if result.plugins else 0
        job_count = len(result.jobs) if result.jobs else 0

        await manager.broadcast({
            "type": "log",
            "level": "success",
            "message": f"Enumerated {plugin_count} plugins and {job_count} jobs"
        })

        session.close()

        return {
            "success": True,
            "plugin_count": plugin_count,
            "job_count": job_count,
            "version": result.version.version if result.version else "Unknown"
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/exploit")
async def run_exploit(request: ExploitRequest):
    """Execute exploit against target"""
    try:
        exploit_log.append({
            "cve": request.cve_id,
            "target": request.target_url,
            "timestamp": datetime.now().isoformat(),
            "status": "running"
        })

        await manager.broadcast({
            "type": "log",
            "level": "info",
            "message": f"Executing {request.cve_id}..."
        })

        session_config = SessionConfig(
            url=request.target_url,
            username=request.username,
            password=request.password,
            timeout=10,
            verify_ssl=False
        )

        session = JenkinsSession(session_config)

        if not session.connect():
            exploit_log[-1]["status"] = "failed"
            return {"success": False, "error": "Failed to connect to target"}

        exploit_module = exploit_registry.get(request.cve_id)

        if not exploit_module:
            exploit_log[-1]["status"] = "failed"
            session.close()
            return {"success": False, "error": f"Exploit not found: {request.cve_id}"}

        metadata = exploit_registry.get_metadata(request.cve_id)

        if metadata.requires_auth and not session.is_authenticated:
            exploit_log[-1]["status"] = "skipped"
            session.close()
            return {"success": False, "error": "Exploit requires authentication"}

        result = exploit_module.run(session, **request.parameters)

        session.close()

        exploit_log[-1]["status"] = result.status

        await manager.broadcast({
            "type": "log",
            "level": "success" if result.status == "success" else "error",
            "message": f"{request.cve_id} execution complete: {result.details}"
        })

        if result.status == "success":
            return {"success": True, "cve_id": request.cve_id, "details": result.details}
        else:
            return {"success": False, "error": result.error or result.details}

    except Exception as e:
        if exploit_log:
            exploit_log[-1]["status"] = "failed"
        return {"success": False, "error": str(e)}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            try:
                data = await websocket.receive_text()
                if data:
                    await manager.broadcast({"type": "log", "level": "info", "message": data})
            except Exception:
                break
    except:
        pass
    finally:
        manager.disconnect(websocket)


@app.get("/api/status")
async def get_status():
    """Get current system status"""
    return {
        "active_sessions": len(sessions),
        "total_exploits": len(exploit_log),
        "successful_exploits": len([e for e in exploit_log if e["status"] == "success"]),
        "failed_exploits": len([e for e in exploit_log if e["status"] == "failed"])
    }


class UILaunchRequest(BaseModel):
    session_id: Optional[str] = None


@app.post("/api/ui/launch_tui")
async def launch_tui(request: UILaunchRequest):
    """
    Launch TUI in new terminal window.
    Optionally pre-load with specified session.
    """
    try:
        success = ui_bridge.launch_tui_with_session(request.session_id)
        
        if success:
            await manager.broadcast({
                "type": "log",
                "level": "success",
                "message": "TUI launched successfully"
            })
            
            return {
                "success": True,
                "message": "TUI launched",
                "session_id": request.session_id
            }
        else:
            return {
                "success": False,
                "error": "Failed to launch TUI"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.post("/api/ui/launch_console")
async def launch_console():
    """Launch Console UI in new terminal window."""
    try:
        success = ui_bridge.launch_console()
        
        if success:
            await manager.broadcast({
                "type": "log",
                "level": "success",
                "message": "Console UI launched successfully"
            })
            
            return {
                "success": True,
                "message": "Console UI launched"
            }
        else:
            return {
                "success": False,
                "error": "Failed to launch Console UI"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/sessions/list")
async def list_sessions():
    """List all active sessions across all UIs."""
    try:
        sessions_list = shared_state.list_sessions()
        
        return {
            "success": True,
            "sessions": [s.to_dict() for s in sessions_list],
            "count": len(sessions_list)
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "sessions": [],
            "count": 0
        }


@app.get("/api/loot/list")
async def list_loot():
    """List all captured loot."""
    try:
        loot = shared_state.get_loot()
        
        return {
            "success": True,
            "loot": loot,
            "credentials_count": len(loot.get('credentials', [])),
            "artifacts_count": len(loot.get('artifacts', []))
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "loot": {"credentials": [], "artifacts": []},
            "credentials_count": 0,
            "artifacts_count": 0
        }


@app.post("/api/exploits/upload")
async def upload_exploit(file: UploadFile = File(...)):
    """
    Upload custom exploit module.
    Validates structure and registers it.
    """
    try:
        if not file.filename.endswith('.py'):
            return {
                "success": False,
                "error": "File must be a Python file (.py)"
            }
        
        content = await file.read()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.py', mode='wb') as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        
        try:
            spec = importlib.util.spec_from_file_location("custom_exploit", tmp_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            from jenkins_breaker.modules.base import ExploitModule
            
            exploit_class = None
            for item in dir(module):
                obj = getattr(module, item)
                if isinstance(obj, type) and issubclass(obj, ExploitModule) and obj != ExploitModule:
                    exploit_class = obj
                    break
            
            if not exploit_class:
                return {
                    "success": False,
                    "error": "No ExploitModule class found in file"
                }
            
            if not hasattr(exploit_class, 'CVE_ID') or not exploit_class.CVE_ID:
                return {
                    "success": False,
                    "error": "ExploitModule must define CVE_ID"
                }
            
            if not hasattr(exploit_class, 'METADATA') or not exploit_class.METADATA:
                return {
                    "success": False,
                    "error": "ExploitModule must define METADATA"
                }
            
            dest = Path("src/jenkins_breaker/modules") / file.filename
            shutil.copy(tmp_path, dest)
            
            exploit_registry.register(exploit_class)
            
            return {
                "success": True,
                "cve_id": exploit_class.CVE_ID,
                "name": exploit_class.METADATA.name,
                "message": f"Exploit {exploit_class.CVE_ID} uploaded and registered successfully"
            }
        
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Upload failed: {str(e)}"
        }


@app.post("/api/operator_scripts/upload")
async def upload_operator_script(file: UploadFile = File(...), category: str = "utility"):
    """
    Upload custom operator script.
    Validates structure and places in correct category directory.
    """
    try:
        if not file.filename.endswith('.py'):
            return {
                "success": False,
                "error": "File must be a Python file (.py)"
            }
        
        valid_categories = ['escalate', 'harvest', 'lateral', 'persist', 'situational', 'exfiltrate', 'utility']
        if category not in valid_categories:
            return {
                "success": False,
                "error": f"Category must be one of: {', '.join(valid_categories)}"
            }
        
        content = await file.read()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.py', mode='wb') as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        
        try:
            spec = importlib.util.spec_from_file_location("custom_script", tmp_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            from jenkins_breaker.ui.ops_scripts.base import OperatorScript
            
            script_class = None
            for item in dir(module):
                obj = getattr(module, item)
                if isinstance(obj, type) and issubclass(obj, OperatorScript) and obj != OperatorScript:
                    script_class = obj
                    break
            
            if not script_class:
                return {
                    "success": False,
                    "error": "No OperatorScript class found in file"
                }
            
            if not hasattr(script_class, 'name') or not script_class.name:
                return {
                    "success": False,
                    "error": "OperatorScript must define 'name' attribute"
                }
            
            if not hasattr(script_class, 'run'):
                return {
                    "success": False,
                    "error": "OperatorScript must implement run() method"
                }
            
            script_dir = Path(f"src/jenkins_breaker/ui/ops_scripts/{category}")
            script_dir.mkdir(parents=True, exist_ok=True)
            
            dest = script_dir / file.filename
            shutil.copy(tmp_path, dest)
            
            return {
                "success": True,
                "name": script_class.name,
                "category": category,
                "message": f"Operator script '{script_class.name}' uploaded successfully to {category} category"
            }
        
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Upload failed: {str(e)}"
        }


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for WebUI."""
    print(f"[*] Starting JenkinsBreaker Web UI on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
