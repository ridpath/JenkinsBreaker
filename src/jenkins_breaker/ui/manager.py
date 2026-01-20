"""
Background job manager for asynchronous exploit execution.
Prevents UI freezing during long-running operations.
"""

import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from jenkins_breaker.core.session import JenkinsSession
from jenkins_breaker.modules.base import ExploitResult, exploit_registry


@dataclass
class Job:
    """Represents a background job."""

    id: int
    exploit: str
    session: JenkinsSession
    options: dict[str, Any]
    status: str = "queued"
    result: Optional[ExploitResult] = None
    started: str = field(default_factory=lambda: datetime.now().isoformat())
    completed: Optional[str] = None
    error: Optional[str] = None
    thread: Optional[threading.Thread] = None


class JobManager:
    """
    Manages background execution of exploits without blocking the UI.

    Features:
    - Asynchronous job execution
    - Job status tracking
    - Result retrieval
    - Job cancellation
    """

    def __init__(self):
        self.jobs: dict[int, Job] = {}
        self.next_job_id = 1
        self.job_queue = queue.Queue()
        self.lock = threading.Lock()
        self.running = True

        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()

    def _worker(self):
        """Background worker thread that processes jobs from the queue."""
        while self.running:
            try:
                job_id = self.job_queue.get(timeout=1)

                with self.lock:
                    if job_id not in self.jobs:
                        continue
                    job = self.jobs[job_id]

                self._execute_job(job)

            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker error: {e}")

    def _execute_job(self, job: Job):
        """Execute a single job."""
        try:
            with self.lock:
                job.status = "running"

            exploit_module = exploit_registry.get(job.exploit)

            if not exploit_module:
                with self.lock:
                    job.status = "failed"
                    job.error = f"Exploit not found: {job.exploit}"
                    job.completed = datetime.now().isoformat()
                return

            kwargs = {}
            if job.options.get('lhost'):
                kwargs['lhost'] = job.options['lhost']
            if job.options.get('lport'):
                kwargs['lport'] = job.options['lport']
            if job.options.get('command'):
                kwargs['command'] = job.options['command']

            result = exploit_module.run(job.session, **kwargs)

            with self.lock:
                job.result = result
                job.status = "completed" if result.status == "success" else "failed"
                job.completed = datetime.now().isoformat()

        except Exception as e:
            with self.lock:
                job.status = "failed"
                job.error = str(e)
                job.completed = datetime.now().isoformat()

    def start_job(
        self,
        exploit: str,
        session: JenkinsSession,
        options: dict[str, Any]
    ) -> int:
        """
        Start a new background job.

        Args:
            exploit: CVE ID of the exploit to run
            session: Active Jenkins session
            options: Exploit options

        Returns:
            Job ID
        """
        with self.lock:
            job_id = self.next_job_id
            self.next_job_id += 1

            job = Job(
                id=job_id,
                exploit=exploit,
                session=session,
                options=options
            )

            self.jobs[job_id] = job
            self.job_queue.put(job_id)

            return job_id

    def get_job(self, job_id: int) -> Optional[Job]:
        """Get job by ID."""
        with self.lock:
            return self.jobs.get(job_id)

    def list_jobs(self) -> dict[int, dict[str, Any]]:
        """
        List all jobs.

        Returns:
            Dictionary of job information
        """
        with self.lock:
            return {
                job_id: {
                    'exploit': job.exploit,
                    'status': job.status,
                    'started': job.started,
                    'completed': job.completed,
                    'error': job.error
                }
                for job_id, job in self.jobs.items()
            }

    def kill_job(self, job_id: int) -> bool:
        """
        Kill a running job.

        Note: This marks the job as killed but doesn't forcefully terminate
        the thread, as that's unsafe in Python.

        Args:
            job_id: ID of job to kill

        Returns:
            True if job was found and killed, False otherwise
        """
        with self.lock:
            if job_id not in self.jobs:
                return False

            job = self.jobs[job_id]
            if job.status in ["queued", "running"]:
                job.status = "killed"
                job.completed = datetime.now().isoformat()
                return True

            return False

    def cleanup_completed(self):
        """Remove completed jobs from memory."""
        with self.lock:
            completed = [
                job_id for job_id, job in self.jobs.items()
                if job.status in ["completed", "failed", "killed"]
            ]
            for job_id in completed:
                del self.jobs[job_id]

    def get_result(self, job_id: int) -> Optional[ExploitResult]:
        """Get the result of a completed job."""
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job.result:
                return job.result
            return None

    def wait_for_job(self, job_id: int, timeout: Optional[float] = None) -> bool:
        """
        Wait for a job to complete.

        Args:
            job_id: ID of job to wait for
            timeout: Maximum time to wait in seconds

        Returns:
            True if job completed, False if timeout or job not found
        """
        start_time = time.time()

        while True:
            with self.lock:
                if job_id not in self.jobs:
                    return False

                job = self.jobs[job_id]
                if job.status in ["completed", "failed", "killed"]:
                    return True

            if timeout and (time.time() - start_time) >= timeout:
                return False

            time.sleep(0.1)

    def shutdown(self):
        """Shutdown the job manager."""
        self.running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)


class AsyncJobExecutor:
    """
    Higher-level executor for running multiple jobs with callbacks.
    """

    def __init__(self, manager: JobManager):
        self.manager = manager

    def execute_async(
        self,
        exploit: str,
        session: JenkinsSession,
        options: dict[str, Any],
        on_complete: Optional[Callable[[ExploitResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None
    ) -> int:
        """
        Execute an exploit asynchronously with callbacks.

        Args:
            exploit: CVE ID
            session: Jenkins session
            options: Exploit options
            on_complete: Callback for successful completion
            on_error: Callback for errors

        Returns:
            Job ID
        """
        job_id = self.manager.start_job(exploit, session, options)

        def monitor():
            """Monitor job and trigger callbacks."""
            self.manager.wait_for_job(job_id)

            job = self.manager.get_job(job_id)
            if not job:
                return

            if job.status == "completed" and job.result and on_complete:
                on_complete(job.result)
            elif job.status == "failed" and on_error:
                error_msg = job.error or "Unknown error"
                on_error(error_msg)

        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()

        return job_id

    def execute_batch(
        self,
        exploits: list[str],
        session: JenkinsSession,
        options: dict[str, Any]
    ) -> list[int]:
        """
        Execute multiple exploits in parallel.

        Args:
            exploits: List of CVE IDs
            session: Jenkins session
            options: Exploit options

        Returns:
            List of job IDs
        """
        job_ids = []
        for exploit in exploits:
            job_id = self.manager.start_job(exploit, session, options)
            job_ids.append(job_id)

        return job_ids

    def wait_for_batch(
        self,
        job_ids: list[int],
        timeout: Optional[float] = None
    ) -> dict[int, ExploitResult]:
        """
        Wait for multiple jobs to complete.

        Args:
            job_ids: List of job IDs
            timeout: Maximum time to wait

        Returns:
            Dictionary of job IDs to results
        """
        results = {}
        start_time = time.time()

        for job_id in job_ids:
            remaining_timeout = None
            if timeout:
                remaining_timeout = timeout - (time.time() - start_time)
                if remaining_timeout <= 0:
                    break

            if self.manager.wait_for_job(job_id, remaining_timeout):
                result = self.manager.get_result(job_id)
                if result:
                    results[job_id] = result

        return results
