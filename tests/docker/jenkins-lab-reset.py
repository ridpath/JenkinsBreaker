"""
Jenkins Lab Reset Script (Python version for cross-platform compatibility)

Resets jenkins-lab Docker container to clean state for test isolation.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import requests


def run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Run shell command and return result."""
    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if check and result.returncode != 0:
        print(f"[!] Command failed with exit code {result.returncode}")
        print(f"[!] stdout: {result.stdout}")
        print(f"[!] stderr: {result.stderr}")
        sys.exit(1)

    return result


def check_docker():
    """Check if Docker is available."""
    result = subprocess.run(
        ["docker", "--version"],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def check_wsl_docker():
    """Check if Docker is available in WSL."""
    result = subprocess.run(
        ["wsl", "-d", "parrot", "--", "docker", "--version"],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def wait_for_jenkins(url: str = "http://localhost:8080", max_wait: int = 120) -> bool:
    """Wait for Jenkins to become ready."""
    print(f"[*] Waiting for Jenkins at {url}...")

    elapsed = 0
    while elapsed < max_wait:
        try:
            response = requests.get(f"{url}/api/json", timeout=5)
            if response.status_code in [200, 403]:
                print(f"[+] Jenkins is ready! (HTTP {response.status_code})")
                return True
        except requests.exceptions.RequestException:
            pass

        time.sleep(2)
        elapsed += 2

        if elapsed % 10 == 0:
            print(f"    Waiting... ({elapsed}/{max_wait} seconds)")

    return False


def reset_jenkins_lab(use_wsl: bool = False):
    """Reset jenkins-lab container to clean state."""
    script_dir = Path(__file__).parent
    jenkins_lab_dir = script_dir.parent.parent / "jenkins-lab"
    docker_compose_file = jenkins_lab_dir / "docker-compose.yml"

    if not docker_compose_file.exists():
        print(f"[!] Error: docker-compose.yml not found at {docker_compose_file}")
        print(f"[!] Looking in: {jenkins_lab_dir}")
        sys.exit(1)

    print("[*] Jenkins Lab Reset Script")
    print("[*] This will stop, remove, and recreate the Jenkins lab container")
    print("")

    os.chdir(jenkins_lab_dir)

    if use_wsl:
        docker_cmd = ["wsl", "-d", "parrot", "--", "docker-compose"]
    else:
        docker_cmd = ["docker-compose"]

    print("[*] Stopping Jenkins lab container...")
    run_command(docker_cmd + ["down"], check=False)

    print("[*] Removing volumes to ensure clean state...")
    run_command(docker_cmd + ["down", "-v"], check=False)

    print("[*] Starting Jenkins lab container...")
    run_command(docker_cmd + ["up", "-d"])

    if wait_for_jenkins():
        print("[+] Jenkins lab reset complete")
        print("[+] Access at: http://localhost:8080")
        print("[+] Credentials: admin/admin")
    else:
        print("[!] Warning: Jenkins may not be fully initialized")
        print("[!] Check container logs: docker logs jenkins-lab")
        print("[!] Or via WSL: wsl -d parrot -- docker logs jenkins-lab")


def main():
    """Main entry point."""
    print("")

    if check_docker():
        print("[+] Docker available locally")
        reset_jenkins_lab(use_wsl=False)
    elif check_wsl_docker():
        print("[+] Docker available in WSL")
        reset_jenkins_lab(use_wsl=True)
    else:
        print("[!] Error: Docker not found")
        print("[!] Please ensure Docker is installed and running")
        print("[!] For WSL: wsl -d parrot -- docker --version")
        sys.exit(1)


if __name__ == "__main__":
    main()
