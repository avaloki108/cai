from __future__ import annotations

import json
from typing import Dict, List, Optional

import requests

from cai.sdk.agents import function_tool
from cai.tools.web.plugin_registry import ExploitPlugin, REGISTRY


@function_tool(strict_mode=False)
def auth_logic_tester(
    endpoint: str,
    method: str = "GET",
    baseline_headers: Optional[Dict[str, str]] = None,
) -> str:
    """
    Test auth logic behavior under token removal/tampering.
    """
    baseline_headers = baseline_headers or {}
    variants = [
        {"name": "no_auth", "headers": {k: v for k, v in baseline_headers.items() if k.lower() != "authorization"}},
        {"name": "invalid_bearer", "headers": {**baseline_headers, "Authorization": "Bearer invalid.invalid.invalid"}},
        {"name": "empty_bearer", "headers": {**baseline_headers, "Authorization": "Bearer "}},
    ]

    results: List[Dict[str, str]] = []
    for variant in variants:
        try:
            resp = requests.request(
                method=method.upper(),
                url=endpoint,
                headers=variant["headers"],
                timeout=10,
                allow_redirects=False,
                verify=False,
            )
            results.append(
                {
                    "variant": variant["name"],
                    "status_code": str(resp.status_code),
                    "content_length": str(len(resp.content)),
                }
            )
        except Exception as exc:  # pylint: disable=broad-except
            results.append({"variant": variant["name"], "error": str(exc)})

    suspicious = [r for r in results if r.get("status_code") in ("200", "201", "204")]
    return json.dumps(
        {
            "endpoint": endpoint,
            "results": results,
            "candidate_bypass": suspicious,
            "confidence": "medium" if suspicious else "low",
        },
        ensure_ascii=True,
    )


REGISTRY.register(
    ExploitPlugin(
        name="auth_logic_tester",
        category="auth_logic",
        execute=auth_logic_tester,
        description="Token tampering and missing-auth behavior tester.",
    )
)
