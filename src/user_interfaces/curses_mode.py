"""
Simple wrapper for the new curses UI structure.
This file now imports and uses the refactored components from the curses folder.
"""

import os
import sys

# Add the curses directory to the path
curses_dir = os.path.join(os.path.dirname(__file__), 'curses')
sys.path.append(curses_dir)

from curse_mode import run_curses_ui


def main():
    """Main entry point for the curses UI"""
    run_curses_ui()


if __name__ == "__main__":
    main()
