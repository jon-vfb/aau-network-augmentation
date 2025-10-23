"""
User Interfaces Module

This module provides different user interface implementations for the network augmentation tool.
Currently supports:
- Curses-based terminal UI
"""

from .curses_mode import run_curses_ui

__all__ = ['run_curses_ui']