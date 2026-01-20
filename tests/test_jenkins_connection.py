"""
Quick test to verify Jenkins lab is accessible before running full test suite.
"""

import sys

import requests


def test_jenkins_connection():
    """Test that Jenkins lab is accessible at localhost:8080."""
    url = "http://localhost:8080/api/json"
    username = "admin"
    password = "admin"

    try:
        response = requests.get(url, auth=(username, password), timeout=10)

        if response.status_code == 200:
            data = response.json()
            version = data.get('version', 'unknown')
            print("[+] Jenkins is accessible!")
            print(f"[+] Version: {version}")
            print("[+] URL: http://localhost:8080")
            return True
        else:
            print(f"[!] Jenkins returned HTTP {response.status_code}")
            return False

    except requests.exceptions.ConnectionError:
        print("[!] Cannot connect to Jenkins at http://localhost:8080")
        print("[!] Is the jenkins-lab Docker container running?")
        print("[!] Start it with: cd jenkins-lab && docker-compose up -d")
        print("[!] Or via WSL: wsl -d parrot -- bash -c 'cd /mnt/c/Users/Chogyam/.zenflow/worktrees/breakapart-db88/JenkinsBreaker/jenkins-lab && docker-compose up -d'")
        return False

    except Exception as e:
        print(f"[!] Error: {e}")
        return False


if __name__ == "__main__":
    success = test_jenkins_connection()
    sys.exit(0 if success else 1)
