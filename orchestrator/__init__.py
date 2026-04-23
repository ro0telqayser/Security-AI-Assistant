"""
orchestrator/__init__.py
=========================
Orchestrator package.

Exports the WorkflowManager and ResultMerger so they can be imported from a
single location:

    from orchestrator import WorkflowManager, ResultMerger

The WorkflowManager coordinates the full scan pipeline. The ResultMerger handles
deduplication of findings from multiple tools.
"""

from .workflow_manager import WorkflowManager
from .result_merger import ResultMerger

__all__ = [
    "WorkflowManager",
    "ResultMerger",
]
