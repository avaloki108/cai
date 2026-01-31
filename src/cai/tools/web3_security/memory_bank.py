"""
Web3 audit memory bank tools.

Stores and retrieves past audit insights using the local vector store.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List

from cai.rag.vector_db import QdrantConnector
from cai.sdk.agents import function_tool


MEMORY_COLLECTION = os.getenv("WEB3_AUDIT_MEMORY_COLLECTION", "web3_audit_memory")


def _parse_tags(tags: str) -> List[str]:
    if not tags:
        return []
    return [t.strip() for t in tags.split(",") if t.strip()]


@function_tool
def web3_memory_add(summary: str, target: str = "", tags: str = "", metadata_json: str = "", ctf=None) -> str:
    """
    Store a Web3 audit insight in the memory bank.

    Args:
        summary: Text summary of the insight or finding.
        target: Optional project/protocol name.
        tags: Optional comma-separated tags.
        metadata_json: Optional JSON string for extra metadata.

    Returns:
        JSON string with status.
    """
    metadata: Dict[str, Any] = {
        "target": target,
        "tags": _parse_tags(tags),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source": "audit",
    }
    if metadata_json:
        try:
            extra = json.loads(metadata_json)
            if isinstance(extra, dict):
                metadata.update(extra)
        except Exception:
            return json.dumps({"error": "Invalid metadata_json"}, indent=2)

    qdrant = QdrantConnector()
    qdrant.add_points(str(uuid.uuid4()), MEMORY_COLLECTION, [summary], [metadata])
    return json.dumps({"status": "ok", "collection": MEMORY_COLLECTION}, indent=2)


@function_tool
def web3_memory_query(query: str, top_k: int = 5, target: str = "", tags: str = "", ctf=None) -> str:
    """
    Query the Web3 audit memory bank for past insights.

    Args:
        query: Search query string.
        top_k: Number of top matches to return.
        target: Optional project/protocol name filter.
        tags: Optional comma-separated tag filter.

    Returns:
        JSON string with matching memory entries.
    """
    qdrant = QdrantConnector()
    results = qdrant.search(MEMORY_COLLECTION, query, limit=top_k)
    tag_set = set(_parse_tags(tags))

    filtered = []
    for item in results:
        meta = item.get("metadata", {}) or {}
        if target and meta.get("target") != target:
            continue
        if tag_set:
            tags_in_item = set(meta.get("tags", []) or [])
            if not tag_set.intersection(tags_in_item):
                continue
        filtered.append(item)

    return json.dumps({
        "query": query,
        "collection": MEMORY_COLLECTION,
        "results": filtered,
    }, indent=2)
