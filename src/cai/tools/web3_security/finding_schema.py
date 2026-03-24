"""Canonical finding schema and normalization helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
import hashlib
import json
import re
import uuid


LOCATION_RE = re.compile(r"^(?P<file>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?$")


def _parse_location(location: str) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    if not location:
        return None, None, None
    match = LOCATION_RE.match(location)
    if not match:
        return None, None, None
    file_path = match.group("file")
    start = match.group("start")
    end = match.group("end")
    return file_path, int(start), int(end) if end else int(start)


def _coerce_confidence(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


@dataclass
class Finding:
    id: str
    tool: str
    type: str
    description: str
    severity: Optional[str] = None
    confidence: Optional[float] = None
    location: str = ""
    file: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    raw: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "type": self.type,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": self.location,
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "metadata": self.metadata,
            "evidence": self.evidence,
            "raw": self.raw,
        }


def _with_location(finding: Finding) -> Finding:
    file_path, start, end = _parse_location(finding.location)
    if file_path and not finding.file:
        finding.file = file_path
    if start is not None and finding.line_start is None:
        finding.line_start = start
    if end is not None and finding.line_end is None:
        finding.line_end = end
    return finding


def normalize_slither(raw: Dict[str, Any]) -> List[Finding]:
    detectors = (raw.get("results") or {}).get("detectors") or []
    findings: List[Finding] = []
    for det in detectors:
        elements = det.get("elements") or []
        location = ""
        if elements:
            source = elements[0].get("source_mapping") or {}
            filename = source.get("filename_absolute") or source.get("filename") or ""
            lines = source.get("lines") or []
            if filename and lines:
                location = f"{filename}:{min(lines)}-{max(lines)}"
            elif filename:
                location = filename

        description = det.get("description") or det.get("markdown") or det.get("check") or ""
        if isinstance(description, list):
            description = "\n".join(description)

        finding = Finding(
            id=str(uuid.uuid4()),
            tool="slither",
            type=det.get("check") or "slither",
            description=description,
            location=location,
            severity=det.get("impact"),
            confidence=_coerce_confidence(det.get("confidence")),
            raw=det,
        )
        findings.append(_with_location(finding))
    return findings


def normalize_mythril(raw: Dict[str, Any]) -> List[Finding]:
    issues = raw.get("issues") or raw.get("issues_found") or []
    findings: List[Finding] = []
    for issue in issues:
        location = issue.get("sourceMap") or issue.get("sourceMapping") or issue.get("address") or ""
        if isinstance(location, dict):
            location = location.get("filename") or location.get("file") or ""
        description = issue.get("description") or issue.get("title") or ""
        issue_type = issue.get("swcID") or issue.get("type") or "mythril"
        finding = Finding(
            id=str(uuid.uuid4()),
            tool="mythril",
            type=str(issue_type),
            description=description,
            location=location or issue.get("function", ""),
            severity=issue.get("severity") or issue.get("impact"),
            confidence=_coerce_confidence(issue.get("confidence")),
            raw=issue,
        )
        findings.append(_with_location(finding))
    return findings


def normalize_generic(raw: Any, tool_name: str) -> List[Finding]:
    if isinstance(raw, list):
        return [ensure_finding_dict(item, tool_name) for item in raw]
    if isinstance(raw, dict):
        for key in ("findings", "issues", "reports", "results", "vulnerabilities"):
            value = raw.get(key)
            if isinstance(value, list):
                return [ensure_finding_dict(item, tool_name) for item in value]
    fallback = Finding(
        id=str(uuid.uuid4()),
        tool=tool_name,
        type=tool_name,
        description=json.dumps(raw)[:2000],
        raw=raw,
    )
    return [_with_location(fallback)]


def normalize_findings(tool_name: str, raw: Any) -> List[Finding]:
    tool = (tool_name or "").lower()
    if tool == "slither" and isinstance(raw, dict):
        return normalize_slither(raw)
    if tool == "mythril" and isinstance(raw, dict):
        return normalize_mythril(raw)
    return normalize_generic(raw, tool or "generic")


def ensure_finding_dict(obj: Any, tool_name: str) -> Finding:
    if isinstance(obj, Finding):
        return _with_location(obj)
    if isinstance(obj, dict):
        description = obj.get("description") or obj.get("message") or ""
        finding_type = obj.get("type") or obj.get("vulnerability_type") or tool_name
        location = obj.get("location") or obj.get("code_context") or ""
        finding = Finding(
            id=str(obj.get("id") or uuid.uuid4()),
            tool=obj.get("tool") or tool_name,
            type=str(finding_type),
            description=str(description),
            location=str(location),
            severity=obj.get("severity"),
            confidence=_coerce_confidence(obj.get("confidence")),
            metadata=obj.get("metadata") or {},
            evidence=obj.get("evidence") or {},
            raw=obj,
        )
        return _with_location(finding)
    return Finding(
        id=str(uuid.uuid4()),
        tool=tool_name,
        type=tool_name,
        description=str(obj),
        raw=obj,
    )


def findings_to_dicts(findings: Iterable[Finding]) -> List[Dict[str, Any]]:
    return [finding.to_dict() for finding in findings]


def to_pipeline_payload(finding: Finding, fallback_contract_path: str = "") -> Dict[str, Any]:
    """Convert normalized schema finding into a deterministic pipeline payload."""
    raw = finding.raw if isinstance(finding.raw, dict) else {}
    element = (raw.get("elements") or [{}])[0] if isinstance(raw, dict) else {}
    source_mapping = element.get("source_mapping") or {}
    contract_obj = element.get("contract")
    if isinstance(contract_obj, dict):
        contract_name = contract_obj.get("name", "unknown")
    elif isinstance(contract_obj, str):
        contract_name = contract_obj
    else:
        contract_name = "unknown"

    external_calls = element.get("external_calls") if isinstance(element, dict) else []
    if not isinstance(external_calls, list):
        external_calls = []

    location = finding.location or finding.file or "unknown"
    if source_mapping.get("filename_short") and source_mapping.get("lines"):
        location = f"{source_mapping.get('filename_short')}:{source_mapping.get('lines')}"

    function_name = "unknown"
    if isinstance(element, dict) and element.get("name"):
        function_name = str(element.get("name"))

    privilege_required = "owner" in function_name.lower() or "onlyowner" in str(location).lower()
    return {
        "id": f"{finding.type}_{hashlib.md5(str(raw).encode()).hexdigest()[:8]}",
        "vulnerability_type": finding.type,
        "severity": finding.severity or "medium",
        "description": finding.description or "",
        "contract": contract_name,
        "function_name": function_name,
        "location": location,
        "contract_path": finding.file or fallback_contract_path,
        "external_call_depth": len(external_calls),
        "cross_contract": any(isinstance(c, dict) and c.get("type") == "external" for c in external_calls),
        "privilege_required": privilege_required,
        "permissionless": not privilege_required,
        "consensus_score": max(0.0, min(1.0, finding.confidence if isinstance(finding.confidence, float) else 0.0)),
        "affected_asset": contract_name,
    }
