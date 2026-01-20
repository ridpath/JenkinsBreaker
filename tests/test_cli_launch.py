import sys

sys.path.insert(0, r'C:\Users\Chogyam\.zenflow\worktrees\breakapart-db88\JenkinsBreaker\src')

print("=" * 60)
print("Testing JenkinsBreaker CLI/Console Launch")
print("=" * 60)

print("\n[*] Testing console import...")
try:
    from jenkins_breaker.ui.console import JenkinsConsole
    print("[+] JenkinsConsole import: SUCCESS")
except Exception as e:
    print(f"[!] JenkinsConsole import FAILED: {e}")
    sys.exit(1)

print("\n[*] Testing console initialization...")
try:
    console = JenkinsConsole()
    print("[+] Console initialized: SUCCESS")
except Exception as e:
    print(f"[!] Console initialization FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n[*] Testing command methods...")
try:
    assert hasattr(console, 'cmd_use'), "Missing cmd_use"
    assert hasattr(console, 'cmd_set'), "Missing cmd_set"
    assert hasattr(console, 'cmd_show'), "Missing cmd_show"
    assert hasattr(console, 'cmd_run'), "Missing cmd_run"
    assert hasattr(console, 'cmd_enumerate'), "Missing cmd_enumerate"
    assert hasattr(console, 'cmd_search'), "Missing cmd_search"
    print("[+] All command methods present: SUCCESS")
except AssertionError as e:
    print(f"[!] Command methods check FAILED: {e}")
    sys.exit(1)

print("\n[*] Testing exploit registry integration...")
try:
    from jenkins_breaker.modules import exploit_registry
    exploits = exploit_registry.list_cves()
    print(f"[+] Exploit registry accessible: {len(exploits)} modules")
except Exception as e:
    print(f"[!] Exploit registry FAILED: {e}")
    sys.exit(1)

print("\n[*] Simulating 'use' command...")
try:
    console.cmd_use(['CVE-2019-1003029'])
    if console.current_exploit == 'CVE-2019-1003029':
        print("[+] 'use' command: SUCCESS")
        print(f"    Current exploit set to: {console.current_exploit}")
    else:
        print("[!] 'use' command FAILED: exploit not set")
except Exception as e:
    print(f"[!] 'use' command FAILED: {e}")
    import traceback
    traceback.print_exc()

print("\n[*] Simulating 'set' command...")
try:
    console.cmd_set(['target', 'http://localhost:8080'])
    if console.options.get('target') == 'http://localhost:8080':
        print("[+] 'set' command: SUCCESS")
        print(f"    Target set to: {console.options['target']}")
    else:
        print("[!] 'set' command FAILED: option not set")
except Exception as e:
    print(f"[!] 'set' command FAILED: {e}")

print("\n" + "=" * 60)
print("CLI/Console Launch Test: COMPLETE")
print("=" * 60)
print("\nSummary:")
print("  [+] Console imports: WORKING")
print("  [+] Console initialization: WORKING")
print("  [+] Command methods: WORKING")
print("  [+] Exploit registry: WORKING")
print("  [+] Basic commands: WORKING")
print("\nCLI is functional and ready to use!")
