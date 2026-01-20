#!/usr/bin/env python3
"""
Screenshot capture script for JenkinsBreaker documentation.
Captures visual assets for README.md and documentation.
"""
import time
import subprocess
import sys
from pathlib import Path
from PIL import ImageGrab, Image, ImageDraw, ImageFont

# Paths
REPO_ROOT = Path(__file__).parent.parent
SCREENSHOTS_DIR = REPO_ROOT / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

def capture_screen(filename: str, bbox=None):
    """Capture screenshot and save to docs/screenshots/"""
    screenshot = ImageGrab.grab(bbox=bbox)
    output_path = SCREENSHOTS_DIR / filename
    screenshot.save(output_path)
    print(f"Saved: {output_path}")
    return screenshot

def capture_cli_help():
    """Capture CLI help output as text-based image"""
    result = subprocess.run(
        [sys.executable, "-m", "jenkins_breaker", "--help"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT
    )
    
    # Create an image from text output
    lines = result.stdout.split('\n')
    
    # Use monospace font if available
    try:
        font = ImageFont.truetype("consola.ttf", 14)
    except:
        font = ImageFont.load_default()
    
    # Calculate image size
    max_width = max(len(line) for line in lines) * 8 + 40
    height = len(lines) * 18 + 40
    
    # Create image
    img = Image.new('RGB', (max_width, height), color='#1e1e1e')
    draw = ImageDraw.Draw(img)
    
    # Draw text
    y = 20
    for line in lines:
        draw.text((20, y), line, fill='#d4d4d4', font=font)
        y += 18
    
    output_path = SCREENSHOTS_DIR / "cli_help.png"
    img.save(output_path)
    print(f"Saved: {output_path}")

def capture_exploit_list():
    """Capture available exploits list"""
    result = subprocess.run(
        [sys.executable, "-m", "jenkins_breaker", "list"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT
    )
    
    lines = result.stdout.split('\n')
    
    try:
        font = ImageFont.truetype("consola.ttf", 12)
    except:
        font = ImageFont.load_default()
    
    max_width = max(len(line) for line in lines if line.strip()) * 7 + 40
    height = len([l for l in lines if l.strip()]) * 16 + 40
    
    img = Image.new('RGB', (max_width, height), color='#1e1e1e')
    draw = ImageDraw.Draw(img)
    
    y = 20
    for line in lines:
        if line.strip():
            draw.text((20, y), line, fill='#d4d4d4', font=font)
            y += 16
    
    output_path = SCREENSHOTS_DIR / "exploit_list.png"
    img.save(output_path)
    print(f"Saved: {output_path}")

def capture_exploit_execution():
    """Capture a simple exploit execution against jenkins-lab"""
    result = subprocess.run(
        [sys.executable, "-m", "jenkins_breaker", 
         "run", "CVE-2024-23897",
         "--target", "http://localhost:8080",
         "--username", "admin",
         "--password", "admin",
         "--file", "/etc/hostname"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30
    )
    
    lines = (result.stdout + result.stderr).split('\n')
    
    try:
        font = ImageFont.truetype("consola.ttf", 12)
    except:
        font = ImageFont.load_default()
    
    max_width = 1000
    height = min(len(lines) * 16 + 40, 800)
    
    img = Image.new('RGB', (max_width, height), color='#1e1e1e')
    draw = ImageDraw.Draw(img)
    
    y = 20
    for line in lines[:50]:  # Limit to first 50 lines
        draw.text((20, y), line[:120], fill='#4ec9b0', font=font)
        y += 16
        if y > height - 40:
            break
    
    output_path = SCREENSHOTS_DIR / "exploit_execution.png"
    img.save(output_path)
    print(f"Saved: {output_path}")

def create_architecture_diagram():
    """Create a simple architecture diagram"""
    width, height = 800, 600
    img = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(img)
    
    try:
        font_title = ImageFont.truetype("arial.ttf", 20)
        font_text = ImageFont.truetype("arial.ttf", 14)
    except:
        font_title = ImageFont.load_default()
        font_text = ImageFont.load_default()
    
    # Title
    draw.text((250, 20), "JenkinsBreaker Architecture", fill='black', font=font_title)
    
    # Boxes
    boxes = [
        (50, 100, 200, 180, "CLI Interface"),
        (250, 100, 400, 180, "TUI"),
        (450, 100, 600, 180, "Web UI"),
        (200, 220, 450, 300, "Core Engine"),
        (50, 340, 200, 420, "Exploit Modules"),
        (250, 340, 400, 420, "Payload Generator"),
        (450, 340, 600, 420, "Post-Exploitation"),
        (250, 460, 400, 540, "Reporting Engine"),
    ]
    
    for x1, y1, x2, y2, label in boxes:
        draw.rectangle([x1, y1, x2, y2], outline='#0066cc', width=2, fill='#e6f2ff')
        text_bbox = draw.textbbox((0, 0), label, font=font_text)
        text_width = text_bbox[2] - text_bbox[0]
        text_x = x1 + (x2 - x1 - text_width) // 2
        text_y = y1 + (y2 - y1) // 2 - 7
        draw.text((text_x, text_y), label, fill='black', font=font_text)
    
    # Arrows
    arrows = [
        (150, 180, 300, 220),
        (350, 180, 300, 220),
        (525, 180, 400, 220),
        (300, 300, 125, 340),
        (300, 300, 325, 340),
        (350, 300, 525, 340),
        (325, 420, 325, 460),
    ]
    
    for x1, y1, x2, y2 in arrows:
        draw.line([x1, y1, x2, y2], fill='#666666', width=2)
        # Arrow head
        draw.polygon([(x2-5, y2-10), (x2+5, y2-10), (x2, y2)], fill='#666666')
    
    output_path = SCREENSHOTS_DIR / "architecture.png"
    img.save(output_path)
    print(f"Saved: {output_path}")

def create_feature_matrix():
    """Create a feature comparison matrix"""
    width, height = 900, 500
    img = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(img)
    
    try:
        font_title = ImageFont.truetype("arial.ttf", 18)
        font_text = ImageFont.truetype("arial.ttf", 12)
    except:
        font_title = ImageFont.load_default()
        font_text = ImageFont.load_default()
    
    draw.text((300, 20), "JenkinsBreaker Capabilities", fill='black', font=font_title)
    
    features = [
        ("Exploit Modules", "28+ CVEs", "High"),
        ("Authentication", "Multi-method", "High"),
        ("Payload Generation", "Multiple formats", "High"),
        ("Post-Exploitation", "Comprehensive", "High"),
        ("Credential Extraction", "16+ types", "High"),
        ("Exploit Chaining", "Automated", "Medium"),
        ("Reporting", "JSON/MD/HTML", "High"),
        ("TUI Interface", "Interactive", "High"),
        ("Web UI", "Dashboard", "Medium"),
        ("Docker Lab", "Testing env", "High"),
    ]
    
    y = 80
    draw.text((50, y), "Feature", fill='black', font=font_title)
    draw.text((350, y), "Capability", fill='black', font=font_title)
    draw.text((650, y), "Maturity", fill='black', font=font_title)
    y += 40
    
    for feature, capability, maturity in features:
        draw.text((50, y), feature, fill='#333333', font=font_text)
        draw.text((350, y), capability, fill='#0066cc', font=font_text)
        
        color = '#00aa00' if maturity == "High" else '#ff9900'
        draw.text((650, y), maturity, fill=color, font=font_text)
        y += 35
    
    output_path = SCREENSHOTS_DIR / "features.png"
    img.save(output_path)
    print(f"Saved: {output_path}")

if __name__ == "__main__":
    print("Capturing JenkinsBreaker screenshots...")
    print(f"Output directory: {SCREENSHOTS_DIR}")
    
    try:
        print("\n[1/6] Capturing CLI help...")
        capture_cli_help()
        
        print("\n[2/6] Capturing exploit list...")
        capture_exploit_list()
        
        print("\n[3/6] Capturing exploit execution...")
        capture_exploit_execution()
        
        print("\n[4/6] Creating architecture diagram...")
        create_architecture_diagram()
        
        print("\n[5/6] Creating feature matrix...")
        create_feature_matrix()
        
        print("\n[6/6] All screenshots captured successfully!")
        print(f"\nScreenshots saved to: {SCREENSHOTS_DIR}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
