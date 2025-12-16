"""
MultiKG Detection Engine
========================
Real-time attack detection using provenance graph matching.
"""

from .log_collector import SysmonCollector, start_collector_thread
from .graph_builder import GraphBuilder
from .matcher import TemplateMatcher

__all__ = [
    'SysmonCollector',
    'start_collector_thread',
    'GraphBuilder',
    'TemplateMatcher'
]
