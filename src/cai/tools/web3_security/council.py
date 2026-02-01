"""
Cross-tool council review to consolidate and label findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cai.sdk.agents import function_tool


def _load_json_input(findings_json_or_path: str) -> Tuple[Any, str]:
    if not findings_json_or_path:
        raise ValueError("findings_json_or_path is required")
    candidate = Path(findings_json_or_path).expanduser()
    if candidate.exists() and candidate.is_file():
        raw = candidate.read_text(encoding="utf-8", errors="ignore")
        return json.loads(raw), str(candidate)
    return json.loads(findings_json_or_path), ""


def _extract_findings(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("filtered_findings", "valid_findings", "findings", "issues", "results"):
            value = raw.get(key)
            if isinstance(value, list):
                return value
        # Triage wrapper
        triage = raw.get("triage")
        if isinstance(triage, dict):
            for key in ("filtered_findings", "valid_findings"):
                value = triage.get(key)
                if isinstance(value, list):
                    return value
    return []


def _finding_key(item: Dict[str, Any]) -> str:
    location = item.get("location") or item.get("code_location") or item.get("source") or ""
    ftype = item.get("type") or item.get("vulnerability_type") or item.get("check") or "unknown"
    function = item.get("function") or item.get("function_name") or ""
    return f"{ftype}|{location}|{function}"


def _extract_confidence(item: Dict[str, Any]) -> float:
    validation = item.get("validation", {}) or {}
    for key in ("confidence", "adjusted_confidence", "validated_confidence"):
        if key in validation and isinstance(validation[key], (int, float)):
            return float(validation[key])
    for key in ("confidence", "validated_confidence"):
        if isinstance(item.get(key), (int, float)):
            return float(item[key])
    if isinstance(item.get("confidence"), str):
        mapping = {"high": 0.9, "medium": 0.6, "low": 0.3}
        return mapping.get(item.get("confidence").lower(), 0.5)
    return 0.5


@function_tool
def council_review(
    findings_json_or_path: str,
    output_path: str = "",
    ctf=None,
) -> str:
    """
    Consolidate findings across tools into Confirmed/Needs Review/Likely FP buckets.
    """
    try:
        raw, source_path = _load_json_input(findings_json_or_path)
    except Exception as exc:
        return json.dumps({"error": f"Failed to parse findings: {exc}"}, indent=2)

    findings = _extract_findings(raw)
    grouped: Dict[str, Dict[str, Any]] = {}

    for item in findings:
        key = _finding_key(item)
        tool = item.get("tool") or item.get("source") or item.get("tool_source") or "unknown"
        entry = grouped.setdefault(key, {
            "canonical": item,
            "sources": set(),
            "confidences": [],
        })
        entry["sources"].add(str(tool))
        entry["confidences"].append(_extract_confidence(item))

    council_findings = []
    confirmed = 0
    needs_review = 0
    likely_fp = 0

    for key, entry in grouped.items():
        sources = sorted(entry["sources"])
        avg_confidence = (
            sum(entry["confidences"]) / len(entry["confidences"])
            if entry["confidences"] else 0.5
        )
        status = "Needs Manual Review"
        if len(sources) >= 2 or avg_confidence >= 0.75:
            status = "Confirmed"
            confirmed += 1
        elif avg_confidence < 0.5:
            status = "Likely False Positive"
            likely_fp += 1
        else:
            needs_review += 1

        canonical = entry["canonical"]
        council_findings.append({
            "type": canonical.get("type") or canonical.get("vulnerability_type") or canonical.get("check"),
            "location": canonical.get("location") or canonical.get("code_location") or canonical.get("source"),
            "description": canonical.get("description") or canonical.get("message"),
            "severity": canonical.get("severity") or canonical.get("impact"),
            "confidence": round(avg_confidence, 3),
            "sources": sources,
            "status": status,
        })

    output = {
        "source_path": source_path,
        "total_findings": len(findings),
        "deduped_findings": len(council_findings),
        "status_counts": {
            "confirmed": confirmed,
            "needs_manual_review": needs_review,
            "likely_false_positive": likely_fp,
        },
        "council_findings": council_findings,
    }

    if output_path:
        out_file = Path(output_path).expanduser()
        out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")

    return json.dumps(output, indent=2)
