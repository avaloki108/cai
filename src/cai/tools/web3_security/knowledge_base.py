"""
Web3 security knowledge base with lightweight RAG retrieval.

Seeds a local vector store with curated best practices and attack vectors,
and provides query and update tools for audits.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from cai.rag.vector_db import QdrantConnector
from cai.sdk.agents import function_tool


KB_COLLECTION = os.getenv("WEB3_KB_COLLECTION", "web3_security_kb")
KB_PATH = Path(__file__).resolve().parent / "data" / "web3_security_kb.jsonl"


def _load_kb_entries() -> List[Dict[str, Any]]:
    if not KB_PATH.exists():
        return []
    entries = []
    for line in KB_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries


def _ensure_kb_seeded(qdrant: QdrantConnector) -> None:
    if qdrant.collection_size(KB_COLLECTION) > 0:
        return
    entries = _load_kb_entries()
    if not entries:
        return
    ids = []
    texts = []
    metadata = []
    for entry in entries:
        text = entry.get("text", "").strip()
        if not text:
            continue
        ids.append(entry.get("id") or str(uuid.uuid4()))
        texts.append(text)
        metadata.append({
            "title": entry.get("title", ""),
            "tags": entry.get("tags", []),
            "source": entry.get("source", "kb"),
        })
    if texts:
        qdrant.add_points(ids, KB_COLLECTION, texts, metadata)


@function_tool
def web3_kb_query(query: str, top_k: int = 5, ctf=None) -> str:
    """
    Query the Web3 security knowledge base for best practices and attack vectors.

    Args:
        query: Search query string.
        top_k: Number of top matches to return.

    Returns:
        JSON string with relevant knowledge base entries.
    """
    qdrant = QdrantConnector()
    _ensure_kb_seeded(qdrant)
    results = qdrant.search(KB_COLLECTION, query, limit=top_k)
    return json.dumps({
        "query": query,
        "collection": KB_COLLECTION,
        "results": results,
    }, indent=2)


@function_tool
def web3_kb_add(entries_json: str, ctf=None) -> str:
    """
    Add custom knowledge base entries.

    Args:
        entries_json: JSON list of entries. Each entry should include:
            - text (required)
            - title (optional)
            - tags (optional list)
            - source (optional)

    Returns:
        JSON string with insert status.
    """
    try:
        data = json.loads(entries_json) if isinstance(entries_json, str) else entries_json
    except Exception:
        return json.dumps({"error": "Invalid JSON for entries_json"}, indent=2)

    if isinstance(data, dict) and "entries" in data:
        entries = data.get("entries", [])
    elif isinstance(data, list):
        entries = data
    else:
        entries = [data]

    qdrant = QdrantConnector()
    _ensure_kb_seeded(qdrant)

    texts = []
    metadata = []
    ids = []
    skipped = 0
    for entry in entries:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        text = entry.get("text", "").strip()
        if not text:
            skipped += 1
            continue
        ids.append(entry.get("id") or str(uuid.uuid4()))
        texts.append(text)
        metadata.append({
            "title": entry.get("title", ""),
            "tags": entry.get("tags", []),
            "source": entry.get("source", "custom"),
        })

    if not texts:
        return json.dumps({"added": 0, "skipped": skipped}, indent=2)

    qdrant.add_points(ids, KB_COLLECTION, texts, metadata)
    return json.dumps({"added": len(texts), "skipped": skipped, "collection": KB_COLLECTION}, indent=2)


@function_tool
def web3_rag_query(query: str, top_k: int = 5, include_memory: bool = True, ctf=None) -> str:
    """
    Unified RAG query across the Web3 knowledge base and audit memory.

    Args:
        query: Search query string.
        top_k: Number of top matches to return per collection.
        include_memory: Include audit memory results when True.

    Returns:
        JSON string with combined results.
    """
    qdrant = QdrantConnector()
    _ensure_kb_seeded(qdrant)
    results = {"knowledge_base": qdrant.search(KB_COLLECTION, query, limit=top_k)}
    if include_memory:
        memory_collection = os.getenv("WEB3_AUDIT_MEMORY_COLLECTION", "web3_audit_memory")
        results["audit_memory"] = qdrant.search(memory_collection, query, limit=top_k)
    return json.dumps({"query": query, "results": results}, indent=2)
