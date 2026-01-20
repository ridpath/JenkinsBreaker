# Screenshots

This directory contains visual documentation for JenkinsBreaker.

## Files

- **architecture.png** (15 KB) - System architecture diagram showing components and data flow
- **features.png** (32 KB) - Feature matrix displaying capabilities and maturity levels
- **cli_help.png** (24 KB) - Command-line interface help output
- **exploit_list.png** (204 KB) - Available exploit modules listing
- **exploit_execution.png** (7 KB) - Example of exploit execution against jenkins-lab
- **tui_interface.png** (75 KB) - Interactive terminal UI mockup
- **webui_dashboard.png** (75 KB) - Web-based dashboard interface mockup

## Generation

Screenshots are generated using automation scripts:

```bash
# Generate CLI and exploit screenshots
python scripts/capture_screenshots.py

# Generate UI interface mockups
python scripts/capture_ui_screenshots.py
```

These scripts:
1. Capture CLI outputs as rendered images
2. Generate architecture and feature diagrams
3. Demonstrate exploit execution
4. Create TUI and WebUI interface mockups
5. Save all assets to this directory

## Usage in Documentation

These screenshots are embedded in:
- `README.md` - Main project documentation
- `docs/modules.md` - Module-specific documentation

All images are version-controlled and committed to the repository.
