from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cai.sdk.agents import function_tool


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _default_log_path() -> str:
    return os.getenv("CAI_OAST_LOG_PATH", ".cai/oast_events.jsonl")


@function_tool(strict_mode=False)
def register_oast_endpoint(
    callback_base_url: str = "",
    label: str = "generic",
    token: str = "",
) -> str:
    """
    Generate a callback token and callback URL for blind checks.
    """
    token = token or secrets.token_hex(8)
    callback_base_url = callback_base_url.rstrip("/")
    callback_url = f"{callback_base_url}/{token}" if callback_base_url else token
    data = {
        "label": label,
        "token": token,
        "callback_url": callback_url,
        "created_at": _now(),
    }
    return json.dumps(data, ensure_ascii=True)


@function_tool(strict_mode=False)
def poll_oast_callbacks(
    token: str = "",
    callback_log_path: str = "",
    channel: Optional[str] = None,
) -> str:
    """
    Read callback events from a JSONL log and filter by token/channel.
    """
    path = callback_log_path or _default_log_path()
    if not os.path.exists(path):
        return json.dumps(
            {"events": [], "path": path, "error": "callback log not found"},
            ensure_ascii=True,
        )

    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if token and event.get("token") != token:
                continue
            if channel and event.get("channel") != channel:
                continue
            events.append(event)

    return json.dumps({"events": events, "path": path, "count": len(events)}, ensure_ascii=True)

