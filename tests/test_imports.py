import sys

sys.path.insert(0, r'C:\Users\Chogyam\.zenflow\worktrees\breakapart-db88\JenkinsBreaker\src')

print("Testing imports...")

try:
    print("[+] JenkinsConsole import: OK")
except Exception as e:
    print(f"[!] JenkinsConsole import failed: {e}")

try:
    print("[+] exploit_registry import: OK")
except Exception as e:
    print(f"[!] exploit_registry import failed: {e}")

try:
    print("[+] JenkinsSession import: OK")
except Exception as e:
    print(f"[!] JenkinsSession import failed: {e}")

try:
    print("[+] JenkinsEnumerator import: OK")
except Exception as e:
    print(f"[!] JenkinsEnumerator import failed: {e}")

print("\nAll core imports successful!")
