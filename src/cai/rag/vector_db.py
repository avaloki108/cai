"""
Local vector store shim for CAI RAG workflows.

Implements a minimal Qdrant-like interface on top of JSONL files using
hashed bag-of-words embeddings. This keeps memory/RAG features working
without external services.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cai.util_file_lock import locked_open

DEFAULT_EMBED_DIM = int(os.getenv("CAI_RAG_EMBED_DIM", "256"))
DEFAULT_RAG_DIR = Path(os.getenv("CAI_RAG_DIR", Path.home() / ".cai" / "rag"))
USE_SMARTBERT = os.getenv("CAI_USE_SMARTBERT", "false").lower() in ("true", "1", "yes")
TOKEN_RE = re.compile(r"[a-z0-9_]+")

# Try to import SmartBERT embedder if enabled
_smartbert_embedder = None
if USE_SMARTBERT:
    try:
        from cai.ml.embeddings import get_embedder
        _smartbert_embedder = get_embedder()
    except ImportError:
        pass  # Fall back to hash-based


def _tokenize(text: str) -> List[str]:
    return TOKEN_RE.findall((text or "").lower())


def _hash_token(token: str, dim: int) -> int:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).hexdigest()
    return int(digest, 16) % dim


def _embed_text(text: str, dim: int) -> List[float]:
    """
    Embed text using SmartBERT (if enabled) or hash-based fallback.
    
    To enable SmartBERT, set environment variable:
        export CAI_USE_SMARTBERT=true
    """
    global _smartbert_embedder
    
    # Use SmartBERT if available
    if _smartbert_embedder is not None:
        try:
            emb = _smartbert_embedder.embed_code(text, normalize=True)
            # Ensure correct dimensionality
            if len(emb) != dim:
                # Resize if dimensions don't match
                if len(emb) > dim:
                    return emb[:dim].tolist()
                else:
                    padded = [0.0] * dim
                    padded[:len(emb)] = emb.tolist()
                    return padded
            return emb.tolist()
        except Exception:
            # Fall through to hash-based on error
            pass
    
    # Hash-based fallback
    vec = [0.0] * dim
    for tok in _tokenize(text):
        vec[_hash_token(tok, dim)] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _dot(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _safe_json_loads(line: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(line)
    except Exception:
        return None


class QdrantConnector:
    """Minimal vector DB interface backed by JSONL files."""

    def __init__(self, base_dir: Optional[str] = None, dim: Optional[int] = None) -> None:
        self.base_dir = Path(base_dir) if base_dir else DEFAULT_RAG_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.dim = int(dim) if dim else DEFAULT_EMBED_DIM

    def _collection_path(self, collection_name: str) -> Path:
        safe = (collection_name or "default").replace("/", "_").strip()
        return self.base_dir / f"{safe}.jsonl"

    def create_collection(self, collection_name: str) -> None:
        path = self._collection_path(collection_name)
        if not path.exists():
            path.write_text("", encoding="utf-8")

    def list_collections(self) -> List[str]:
        return [p.stem for p in self.base_dir.glob("*.jsonl")]

    def collection_size(self, collection_name: str) -> int:
        path = self._collection_path(collection_name)
        if not path.exists():
            return 0
        return sum(1 for _ in path.read_text(encoding="utf-8").splitlines() if _.strip())

    def add_points(
        self,
        id_point: Any,
        collection_name: str,
        texts: Iterable[str],
        metadata: Iterable[Dict[str, Any]],
    ) -> bool:
        self.create_collection(collection_name)
        path = self._collection_path(collection_name)

        if isinstance(texts, (str, bytes)):
            texts_list = [str(texts)]
        else:
            texts_list = list(texts) if isinstance(texts, Iterable) else [str(texts)]

        if isinstance(metadata, dict):
            metadata_list = [metadata]
        elif isinstance(metadata, (str, bytes)):
            metadata_list = [{}]
        else:
            metadata_list = list(metadata) if isinstance(metadata, Iterable) else [{}]

        if not metadata_list:
            metadata_list = [{}] * len(texts_list)
        if len(metadata_list) == 1 and len(texts_list) > 1:
            metadata_list = metadata_list * len(texts_list)
        if len(metadata_list) != len(texts_list):
            metadata_list = (metadata_list + [{}] * len(texts_list))[: len(texts_list)]

        if isinstance(id_point, Iterable) and not isinstance(id_point, (str, bytes)):
            ids = list(id_point)
        else:
            ids = [id_point] * len(texts_list)

        records = []
        for idx, text in enumerate(texts_list):
            record_id = ids[idx] if ids[idx] is not None else str(uuid.uuid4())
            record = {
                "id": str(record_id),
                "text": text,
                "metadata": metadata_list[idx],
                "vector": _embed_text(text, self.dim),
            }
            records.append(record)

        with locked_open(str(path), "a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=True) + "\n")

        return True

    def _load_collection(self, collection_name: str) -> List[Dict[str, Any]]:
        path = self._collection_path(collection_name)
        if not path.exists():
            return []
        entries = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = _safe_json_loads(line)
            if record:
                entries.append(record)
        return entries

    def search(self, collection_name: str, query_text: str, limit: int = 3) -> List[Dict[str, Any]]:
        query_vec = _embed_text(query_text or "", self.dim)

        collections = []
        if collection_name == "_all_":
            collections = self.list_collections()
        else:
            collections = [collection_name]

        results = []
        for coll in collections:
            for record in self._load_collection(coll):
                vec = record.get("vector", [])
                if not vec:
                    continue
                score = _dot(query_vec, vec)
                results.append({
                    "id": record.get("id"),
                    "score": float(score),
                    "text": record.get("text", ""),
                    "metadata": record.get("metadata", {}),
                    "collection": coll,
                })

        results.sort(key=lambda r: r["score"], reverse=True)
        return results[: max(int(limit), 1)]


def _format_results(results: List[Dict[str, Any]]) -> str:
    if not results:
        return ""
    lines = []
    for item in results:
        score = item.get("score", 0.0)
        meta = item.get("metadata", {}) or {}
        title = meta.get("title") or meta.get("name") or meta.get("target") or ""
        header = f"score={score:.3f}"
        if title:
            header = f"{header} | {title}"
        lines.append(f"- {header}\n{item.get('text', '')}")
    return "\n".join(lines)


def get_previous_memory(query: str, limit: int = 5) -> str:
    """Return formatted memory entries for prompts."""
    qdrant = QdrantConnector()
    results = qdrant.search(collection_name="_all_", query_text=query or "", limit=limit)
    return _format_results(results)
