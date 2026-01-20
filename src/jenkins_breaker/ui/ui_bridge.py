"""
UI Communication Bridge for inter-UI communication.
Provides WebSocket server for real-time updates and UI launching capabilities.
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, Set

import websockets

from jenkins_breaker.ui.shared_state import SharedStateManager, shared_state


class UIBridge:
    """
    Bridge for communication between different UIs.
    
    Features:
    - WebSocket server for real-time UI-to-UI communication
    - Event broadcasting to connected UIs
    - UI launching capabilities (TUI from Web UI, etc.)
    - Cross-UI session synchronization
    """
    
    def __init__(
        self,
        shared_state: SharedStateManager,
        host: str = '127.0.0.1',
        port: int = 8765
    ):
        self.shared_state = shared_state
        self.host = host
        self.port = port
        
        self.connected_clients: Set[websockets.WebSocketServerProtocol] = set()
        self.client_metadata: dict[websockets.WebSocketServerProtocol, dict] = {}
        
        self._server = None
        self._server_thread: Optional[threading.Thread] = None
        self._running = False
        
        self.shared_state.subscribe_to_events(self._handle_state_event)
    
    def _handle_state_event(self, event_type: str, data: dict[str, Any]):
        """Handle events from shared state and broadcast to UIs."""
        if self._running:
            asyncio.run(self.broadcast_event(event_type, data))
    
    async def _handle_client(self, websocket: websockets.WebSocketServerProtocol, path: str):
        """Handle individual WebSocket client connection."""
        self.connected_clients.add(websocket)
        
        client_info = {
            'connected_at': datetime.now().isoformat(),
            'ui_type': 'unknown'
        }
        self.client_metadata[websocket] = client_info
        
        try:
            await websocket.send(json.dumps({
                'type': 'connected',
                'message': 'Connected to JenkinsBreaker UI Bridge',
                'timestamp': datetime.now().isoformat()
            }))
            
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self._process_message(websocket, data)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Invalid JSON'
                    }))
        
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.connected_clients.discard(websocket)
            self.client_metadata.pop(websocket, None)
    
    async def _process_message(
        self,
        websocket: websockets.WebSocketServerProtocol,
        data: dict[str, Any]
    ):
        """Process incoming message from client."""
        msg_type = data.get('type')
        
        if msg_type == 'register':
            ui_type = data.get('ui_type', 'unknown')
            self.client_metadata[websocket]['ui_type'] = ui_type
            
            await websocket.send(json.dumps({
                'type': 'registered',
                'ui_type': ui_type,
                'timestamp': datetime.now().isoformat()
            }))
        
        elif msg_type == 'get_sessions':
            sessions = [s.to_dict() for s in self.shared_state.list_sessions()]
            
            await websocket.send(json.dumps({
                'type': 'sessions',
                'data': sessions,
                'timestamp': datetime.now().isoformat()
            }))
        
        elif msg_type == 'get_loot':
            loot = self.shared_state.get_loot()
            
            await websocket.send(json.dumps({
                'type': 'loot',
                'data': loot,
                'timestamp': datetime.now().isoformat()
            }))
        
        elif msg_type == 'get_stats':
            stats = self.shared_state.get_stats()
            
            await websocket.send(json.dumps({
                'type': 'stats',
                'data': stats,
                'timestamp': datetime.now().isoformat()
            }))
        
        elif msg_type == 'ping':
            await websocket.send(json.dumps({
                'type': 'pong',
                'timestamp': datetime.now().isoformat()
            }))
    
    async def broadcast_event(self, event_type: str, data: dict[str, Any]):
        """
        Broadcast event to all connected UIs.
        
        Args:
            event_type: Type of event
            data: Event data
        """
        if not self.connected_clients:
            return
        
        message = json.dumps({
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
        
        dead_clients = set()
        
        for client in self.connected_clients:
            try:
                await client.send(message)
            except Exception:
                dead_clients.add(client)
        
        for client in dead_clients:
            self.connected_clients.discard(client)
            self.client_metadata.pop(client, None)
    
    async def start_websocket_server(self):
        """Start WebSocket server for UI communication."""
        try:
            self._server = await websockets.serve(
                self._handle_client,
                self.host,
                self.port
            )
            
            self._running = True
            
            print(f"[+] UI Bridge WebSocket server started on ws://{self.host}:{self.port}")
            
            await asyncio.Future()
        
        except Exception as e:
            print(f"[!] Failed to start UI Bridge: {e}")
            self._running = False
    
    def start(self):
        """Start the UI Bridge in a background thread."""
        if not self._running:
            self._server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self._server_thread.start()
    
    def _run_server(self):
        """Run server in thread."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(self.start_websocket_server())
        except KeyboardInterrupt:
            pass
        finally:
            loop.close()
    
    def stop(self):
        """Stop the UI Bridge."""
        self._running = False
        
        if self._server:
            self._server.close()
    
    def launch_tui_with_session(self, session_id: Optional[str] = None) -> bool:
        """
        Launch TUI with specific session pre-loaded.
        
        Args:
            session_id: Optional session to load
        
        Returns:
            True if launched successfully
        """
        try:
            project_root = Path(__file__).parent.parent.parent.parent
            launch_script = project_root / "launch_tui.py"
            
            if not launch_script.exists():
                print(f"[!] TUI launcher not found: {launch_script}")
                return False
            
            cmd = [sys.executable, str(launch_script)]
            
            if session_id:
                cmd.extend(["--session", session_id])
            
            if sys.platform == "win32":
                subprocess.Popen(
                    ["start", "cmd", "/k"] + cmd,
                    shell=True,
                    cwd=str(project_root)
                )
            elif sys.platform == "darwin":
                subprocess.Popen(
                    ["osascript", "-e", f'tell app "Terminal" to do script "{" ".join(cmd)}"'],
                    cwd=str(project_root)
                )
            else:
                terminals = [
                    "x-terminal-emulator",
                    "gnome-terminal",
                    "konsole",
                    "xterm"
                ]
                
                for terminal in terminals:
                    try:
                        subprocess.Popen(
                            [terminal, "-e"] + cmd,
                            cwd=str(project_root)
                        )
                        break
                    except FileNotFoundError:
                        continue
            
            return True
        
        except Exception as e:
            print(f"[!] Failed to launch TUI: {e}")
            return False
    
    def launch_webui(self, port: int = 8000) -> bool:
        """
        Launch Web UI in browser.
        
        Args:
            port: Port to run Web UI on
        
        Returns:
            True if launched successfully
        """
        try:
            project_root = Path(__file__).parent.parent.parent.parent
            launch_script = project_root / "launch_webui.py"
            
            if not launch_script.exists():
                print(f"[!] Web UI launcher not found: {launch_script}")
                return False
            
            subprocess.Popen(
                [sys.executable, str(launch_script), "--port", str(port)],
                cwd=str(project_root)
            )
            
            import time
            time.sleep(2)
            
            webbrowser.open(f"http://127.0.0.1:{port}")
            
            return True
        
        except Exception as e:
            print(f"[!] Failed to launch Web UI: {e}")
            return False
    
    def launch_console(self) -> bool:
        """
        Launch Console UI in new terminal.
        
        Returns:
            True if launched successfully
        """
        try:
            project_root = Path(__file__).parent.parent.parent.parent
            launch_script = project_root / "launch_console.py"
            
            if not launch_script.exists():
                print(f"[!] Console launcher not found: {launch_script}")
                return False
            
            cmd = [sys.executable, str(launch_script)]
            
            if sys.platform == "win32":
                subprocess.Popen(
                    ["start", "cmd", "/k"] + cmd,
                    shell=True,
                    cwd=str(project_root)
                )
            else:
                subprocess.Popen(
                    ["x-terminal-emulator", "-e"] + cmd,
                    cwd=str(project_root)
                )
            
            return True
        
        except Exception as e:
            print(f"[!] Failed to launch Console: {e}")
            return False
    
    def get_ui_status(self) -> dict[str, Any]:
        """
        Get status of all running UIs.
        
        Returns:
            Dictionary with UI status information
        """
        return {
            'bridge_running': self._running,
            'connected_clients': len(self.connected_clients),
            'clients': [
                {
                    'ui_type': meta.get('ui_type'),
                    'connected_at': meta.get('connected_at')
                }
                for meta in self.client_metadata.values()
            ]
        }


ui_bridge = UIBridge(shared_state)
