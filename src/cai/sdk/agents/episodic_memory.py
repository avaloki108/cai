"""Episodic memory for capturing tool failures (Reflexion-style)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from cai.util_file_lock import locked_open


DEFAULT_MEMORY_PATH = Path(
    os.getenv(
        "CAI_EPISODIC_MEMORY_PATH",
        Path.home() / ".cai" / "episodic_failures.jsonl",
    )
)


def record_failure(event: Dict[str, Any]) -> None:
    """Append a failure event to episodic memory."""
    DEFAULT_MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event,
    }
    with locked_open(str(DEFAULT_MEMORY_PATH), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def load_recent_failures(limit: int = 5) -> List[Dict[str, Any]]:
    """Return the most recent failure events."""
    if not DEFAULT_MEMORY_PATH.exists():
        return []
    try:
        lines = DEFAULT_MEMORY_PATH.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    entries = []
    for line in lines[-limit:]:
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries


def format_failures(failures: List[Dict[str, Any]]) -> str:
    """Human-readable summary of failures for prompt context."""
    if not failures:
        return ""
    lines = ["Recent tool failures to avoid repeating:"]
    for item in failures:
        tool = item.get("tool", "unknown")
        error = item.get("error", "unknown error")
        context = item.get("context", "")
        lines.append(f"- {tool}: {error} {f'({context})' if context else ''}")
    return "\n".join(lines)
