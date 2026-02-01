"""Incremental analysis helpers for large repositories."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from cai.sdk.agents import function_tool


IMPORT_RE = re.compile(r'import\\s+(?:\\{[^}]+\\}\\s+from\\s+)?["\\\']([^"\\\']+)["\\\'];?')


def _repo_snapshot_path(repo_path: Path) -> Path:
    repo_hash = hashlib.sha256(str(repo_path.resolve()).encode("utf-8")).hexdigest()[:12]
    base_dir = Path(os.getenv("CAI_AUDIT_SNAPSHOT_DIR", Path.home() / ".cai" / "audit_snapshots"))
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / f"{repo_hash}.json"


def _snapshot_files(repo_path: Path) -> Dict[str, Dict[str, int]]:
    files = {}
    for sol_file in repo_path.rglob("*.sol"):
        try:
            stat = sol_file.stat()
            rel = str(sol_file.relative_to(repo_path))
            files[rel] = {"mtime": int(stat.st_mtime), "size": int(stat.st_size)}
        except OSError:
            continue
    return files


def _load_snapshot(snapshot_path: Path) -> Dict[str, Dict[str, int]]:
    if not snapshot_path.exists():
        return {}
    try:
        data = json.loads(snapshot_path.read_text(encoding="utf-8"))
        return data.get("files", {})
    except Exception:
        return {}


def _write_snapshot(snapshot_path: Path, files: Dict[str, Dict[str, int]]) -> None:
    payload = {"files": files}
    snapshot_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _parse_imports(repo_path: Path, rel_path: str) -> Set[str]:
    file_path = repo_path / rel_path
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return set()
    imports = set()
    for match in IMPORT_RE.findall(content):
        if match.startswith("."):
            resolved = (file_path.parent / match).resolve()
            try:
                rel = str(resolved.relative_to(repo_path))
                if rel.endswith(".sol"):
                    imports.add(rel)
            except Exception:
                continue
    return imports


def _build_reverse_deps(repo_path: Path, files: List[str]) -> Dict[str, Set[str]]:
    reverse: Dict[str, Set[str]] = {}
    for rel in files:
        for imp in _parse_imports(repo_path, rel):
            reverse.setdefault(imp, set()).add(rel)
    return reverse


def _expand_dependencies(changed: Set[str], reverse_deps: Dict[str, Set[str]]) -> Set[str]:
    expanded = set(changed)
    queue = list(changed)
    while queue:
        current = queue.pop()
        for dep in reverse_deps.get(current, set()):
            if dep not in expanded:
                expanded.add(dep)
                queue.append(dep)
    return expanded


@function_tool
def detect_incremental_contracts(repo_path: str, update_snapshot: bool = True, ctf=None) -> str:
    """
    Detect changed Solidity files and invalidate dependents.
    """
    repo = Path(repo_path).expanduser()
    snapshot_path = _repo_snapshot_path(repo)

    current_files = _snapshot_files(repo)
    previous_files = _load_snapshot(snapshot_path)

    current_set = set(current_files.keys())
    previous_set = set(previous_files.keys())

    added = sorted(current_set - previous_set)
    removed = sorted(previous_set - current_set)
    changed = sorted(
        rel
        for rel in current_set & previous_set
        if current_files[rel] != previous_files.get(rel)
    )

    changed_set = set(added + changed)
    reverse_deps = _build_reverse_deps(repo, list(current_set))
    invalidated = sorted(_expand_dependencies(changed_set, reverse_deps))

    if update_snapshot:
        _write_snapshot(snapshot_path, current_files)

    return json.dumps(
        {
            "repo_path": str(repo),
            "snapshot_path": str(snapshot_path),
            "total_files": len(current_files),
            "added": added,
            "removed": removed,
            "changed": changed,
            "invalidated": invalidated,
        },
        indent=2,
    )
