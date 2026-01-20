#!/usr/bin/env python3
"""
JenkinsBreaker Console Launcher
Starts the interactive REPL console interface.
"""

import sys
from pathlib import Path

from jenkins_breaker.ui.console import JenkinsConsole
from jenkins_breaker.utils.logger import setup_logging


def main():
    setup_logging(console_output=True)
    
    print("""
    ==================================================================
                      JenkinsBreaker Console                       
              Interactive Command-Line Interface                   
    ==================================================================
    
    Type 'help' for available commands
    Type 'exit' or 'quit' to exit
    """)
    
    console = JenkinsConsole()
    
    try:
        console.run()
    except KeyboardInterrupt:
        print("\n[*] Exiting console...")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
