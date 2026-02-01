"""
Tool-specific triage for audit findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cai.sdk.agents import function_tool
from .validate_findings import _filter_false_positives_impl
from .finding_schema import normalize_findings, findings_to_dicts




def _load_json_input(findings_json_or_path: str) -> Tuple[Any, str]:
    if not findings_json_or_path:
        raise ValueError("findings_json_or_path is required")
    candidate = Path(findings_json_or_path).expanduser()
    if candidate.exists() and candidate.is_file():
        raw = candidate.read_text(encoding="utf-8", errors="ignore")
        return json.loads(raw), str(candidate)
    return json.loads(findings_json_or_path), ""


def _normalize_findings(tool_name: str, raw: Any) -> List[Dict[str, Any]]:
    return findings_to_dicts(normalize_findings(tool_name, raw))


@function_tool
def triage_findings(
    tool_name: str,
    findings_json_or_path: str,
    min_confidence: float = 0.5,
    output_path: str = "",
    ctf=None,
) -> str:
    """
    Run tool-specific triage on findings and filter false positives.
    """
    try:
        raw, source_path = _load_json_input(findings_json_or_path)
    except Exception as exc:
        return json.dumps({"error": f"Failed to parse findings: {exc}"}, indent=2)

    normalized = _normalize_findings(tool_name, raw)
    triage_json = _filter_false_positives_impl(
        findings_json=normalized,
        tool_source=tool_name or "generic",
        min_confidence=min_confidence,
    )

    if isinstance(triage_json, dict):
        triage_result = triage_json
    else:
        try:
            triage_result = json.loads(triage_json)
        except Exception:
            triage_result = {"raw": triage_json}

    output = {
        "tool": tool_name,
        "source_path": source_path,
        "normalized_count": len(normalized),
        "triage": triage_result,
    }

    if output_path:
        out_file = Path(output_path).expanduser()
        out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")

    return json.dumps(output, indent=2)
