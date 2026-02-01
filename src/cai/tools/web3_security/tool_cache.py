"""Tool result caching keyed by target fingerprint + args."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional


CACHE_DIR = Path(os.getenv("CAI_TOOL_CACHE_DIR", Path.home() / ".cai" / "tool_cache"))
DEFAULT_TTL = int(os.getenv("CAI_TOOL_CACHE_TTL_SEC", "3600"))


def _fingerprint_file(path: Path) -> str:
    hasher = hashlib.sha256()
    try:
        hasher.update(path.read_bytes())
    except OSError:
        hasher.update(str(path).encode("utf-8"))
    return hasher.hexdigest()


def _fingerprint_dir(path: Path) -> str:
    hasher = hashlib.sha256()
    for root, _, files in os.walk(path):
        for name in sorted(files):
            file_path = Path(root) / name
            try:
                stat = file_path.stat()
                rel = str(file_path.relative_to(path))
                hasher.update(rel.encode("utf-8"))
                hasher.update(str(stat.st_mtime_ns).encode("utf-8"))
                hasher.update(str(stat.st_size).encode("utf-8"))
            except OSError:
                continue
    return hasher.hexdigest()


def fingerprint_target(target: str) -> str:
    if target.startswith("0x"):
        return target
    path = Path(target)
    if path.is_file():
        return _fingerprint_file(path)
    if path.is_dir():
        return _fingerprint_dir(path)
    return target


def _cache_path(tool_name: str, key: str) -> Path:
    tool_dir = CACHE_DIR / tool_name
    tool_dir.mkdir(parents=True, exist_ok=True)
    return tool_dir / f"{key}.json"


def _cache_key(tool_name: str, target: str, args: Dict[str, Any]) -> str:
    payload = {
        "tool": tool_name,
        "target": fingerprint_target(target),
        "args": args,
    }
    raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_cached_result(
    tool_name: str,
    target: str,
    args: Dict[str, Any],
    ttl_sec: Optional[int] = None,
) -> Optional[str]:
    ttl = DEFAULT_TTL if ttl_sec is None else ttl_sec
    key = _cache_key(tool_name, target, args)
    cache_file = _cache_path(tool_name, key)
    if not cache_file.exists():
        return None
    try:
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
    except Exception:
        return None
    created_at = payload.get("created_at", 0)
    if ttl and (time.time() - created_at) > ttl:
        return None
    return payload.get("result")


def save_cached_result(
    tool_name: str,
    target: str,
    args: Dict[str, Any],
    result: str,
) -> None:
    key = _cache_key(tool_name, target, args)
    cache_file = _cache_path(tool_name, key)
    payload = {
        "created_at": time.time(),
        "tool": tool_name,
        "target": target,
        "result": result,
    }
    cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
