import sys

sys.path.insert(0, r'C:\Users\Chogyam\.zenflow\worktrees\breakapart-db88\JenkinsBreaker\src')

from jenkins_breaker.modules import exploit_registry

print(f'Total modules registered: {len(exploit_registry.list_cves())}')
print('\nAll registered modules:')
for cve in sorted(exploit_registry.list_cves()):
    print(f'  - {cve}')
