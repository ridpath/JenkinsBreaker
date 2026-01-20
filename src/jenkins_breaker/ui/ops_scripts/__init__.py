"""Operator scripts for post-exploitation activities.

This package contains sophisticated Python-based operator scripts
organized by tactical category (escalate, harvest, lateral, persist, etc.).
"""

from .base import OperatorScript, ScriptResult

__all__ = ['OperatorScript', 'ScriptResult']
