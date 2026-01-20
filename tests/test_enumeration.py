import sys

sys.path.insert(0, r'C:\Users\Chogyam\.zenflow\worktrees\breakapart-db88\JenkinsBreaker\src')

from jenkins_breaker.core.enumeration import JenkinsEnumerator

print("=" * 60)
print("Testing JenkinsBreaker Enumeration")
print("=" * 60)

enumerator = JenkinsEnumerator(
    base_url="http://localhost:8080",
    auth=("admin", "admin"),
    verify_ssl=False
)

print("\n[*] Testing version detection...")
try:
    version = enumerator.detect_version()
    if version:
        print(f"[+] Jenkins Version: {version.version}")
        print(f"    LTS: {version.is_lts}")
        print(f"    Source: {version.source}")
    else:
        print("[!] Could not detect version")
except Exception as e:
    print(f"[!] Version detection failed: {e}")

print("\n[*] Testing plugin enumeration...")
try:
    plugins = enumerator.enumerate_plugins()
    print(f"[+] Found {len(plugins)} plugins")
    if plugins:
        print("    Sample plugins:")
        for plugin in list(plugins)[:5]:
            print(f"      - {plugin.short_name}:{plugin.version}")
except Exception as e:
    print(f"[!] Plugin enumeration failed: {e}")

print("\n[*] Testing job enumeration...")
try:
    jobs = enumerator.enumerate_jobs()
    print(f"[+] Found {len(jobs)} jobs")
    if jobs:
        for job in jobs[:5]:
            print(f"      - {job.name}")
except Exception as e:
    print(f"[!] Job enumeration failed: {e}")

print("\n[*] Testing full enumeration...")
try:
    result = enumerator.enumerate_all()
    print("[+] Full enumeration complete")
    if result.version:
        print(f"    Version: {result.version.version}")
    print(f"    Plugins: {len(result.plugins)}")
    print(f"    Jobs: {len(result.jobs)}")
    print(f"    Vulnerabilities detected: {len(result.vulnerabilities)}")
    if result.vulnerabilities:
        print("    Sample vulnerabilities:")
        for vuln in result.vulnerabilities[:3]:
            print(f"      - {vuln.get('cve', 'unknown')}: {vuln.get('description', 'unknown')}")
except Exception as e:
    print(f"[!] Full enumeration failed: {e}")

print("\n" + "=" * 60)
print("Enumeration Test Complete")
print("=" * 60)
