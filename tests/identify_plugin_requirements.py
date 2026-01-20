import sys

sys.path.insert(0, r'C:\Users\Chogyam\.zenflow\worktrees\breakapart-db88\JenkinsBreaker\src')


from jenkins_breaker.modules import exploit_registry

print("=" * 80)
print("Plugin Requirements Analysis for All CVE Modules")
print("=" * 80)

all_exploits = exploit_registry.list_all()

plugin_requirements = {}

for cve_id, metadata in sorted(all_exploits.items()):
    if not cve_id.startswith('CVE'):
        continue

    print(f"\n{cve_id}: {metadata.name}")
    print("-" * 80)
    print(f"Description: {metadata.description}")
    print(f"Severity: {metadata.severity}")
    print(f"Affected Versions: {metadata.affected_versions}")
    print(f"Requires Auth: {metadata.requires_auth}")
    print(f"Tags: {', '.join(metadata.tags)}")

    plugins_needed = []

    desc_lower = metadata.description.lower()
    name_lower = metadata.name.lower()
    tags_str = ' '.join(metadata.tags).lower()
    all_text = f"{desc_lower} {name_lower} {tags_str}"

    if 'script security' in all_text or 'script-security' in all_text:
        plugins_needed.append('script-security')
    if 'pipeline' in all_text or 'workflow' in all_text:
        plugins_needed.append('workflow-cps')
    if 'groovy' in all_text:
        if 'script security' not in all_text:
            plugins_needed.append('workflow-cps')
    if 'git' in all_text:
        plugins_needed.append('git')
    if 'credential' in all_text:
        plugins_needed.append('credentials')
    if 'matrix' in all_text:
        plugins_needed.append('matrix-auth')
    if 'agent' in all_text or 'slave' in all_text:
        plugins_needed.append('ssh-slaves')
    if 'cli' in all_text:
        plugins_needed.append('remoting')
    if 'stapler' in all_text:
        pass

    if plugins_needed:
        print(f"Likely Required Plugins: {', '.join(set(plugins_needed))}")
    else:
        print("Likely Required Plugins: Core Jenkins (no special plugins)")

    if metadata.references:
        print("References:")
        for ref in metadata.references[:2]:
            print(f"  - {ref}")

    plugin_requirements[cve_id] = list(set(plugins_needed)) if plugins_needed else ['core']

print("\n" + "=" * 80)
print("Summary: Plugin Requirements by CVE")
print("=" * 80)

core_only = []
needs_plugins = {}

for cve, plugins in sorted(plugin_requirements.items()):
    if plugins == ['core']:
        core_only.append(cve)
    else:
        for plugin in plugins:
            if plugin not in needs_plugins:
                needs_plugins[plugin] = []
            needs_plugins[plugin].append(cve)

print(f"\nCVEs requiring only core Jenkins ({len(core_only)}):")
for cve in core_only:
    print(f"  - {cve}")

print(f"\nCVEs requiring specific plugins ({len(plugin_requirements) - len(core_only)}):")
for plugin, cves in sorted(needs_plugins.items()):
    print(f"\n  Plugin: {plugin} ({len(cves)} CVEs)")
    for cve in cves:
        print(f"    - {cve}")

print("\n" + "=" * 80)
print("Recommended plugins.txt additions:")
print("=" * 80)
unique_plugins = set()
for plugins in plugin_requirements.values():
    if plugins != ['core']:
        unique_plugins.update(plugins)

for plugin in sorted(unique_plugins):
    print(f"{plugin}:latest")
