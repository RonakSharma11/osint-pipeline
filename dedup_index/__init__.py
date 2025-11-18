# dedup_index/__init__.py
"""
dedup_index package

Provides:
- Indexer class for storing and merging IOCs
- Deduplication helpers: canonicalize, compute_confidence, make_cluster_id
"""

from .indexer import Indexer
from .deduplicator import canonicalize, compute_confidence, make_cluster_id

__all__ = [
    "Indexer",
    "canonicalize",
    "compute_confidence",
    "make_cluster_id"
]
