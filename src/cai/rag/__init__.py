"""
Local RAG utilities for CAI.

This package provides a lightweight vector store implementation used by
the memory and RAG tools when an external database is not available.
"""

from .vector_db import QdrantConnector, get_previous_memory

__all__ = [
    "QdrantConnector",
    "get_previous_memory",
]
