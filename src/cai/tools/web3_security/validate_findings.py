"""
Validation tool for filtering false positives from security analysis results.

This tool helps distinguish between genuine vulnerabilities and false positives
by analyzing findings in context of the actual code and known patterns.
"""

from cai.sdk.agents import function_tool
import json
import re


@function_tool
def validate_finding(
    finding_type: str,
    finding_description: str,
    code_context: str = "",
    tool_source: str = "slither"
) -> str:
    """
    Validate a security finding to determine if it's a genuine vulnerability or false positive.
    
    This tool analyzes findings from static analysis tools (Slither, Mythril, etc.) and
    filters out common false positives by checking:
    - Context and code patterns
    - Known false positive patterns
    - Actual exploitability
    - Tool-specific noise patterns
    
    Args:
        finding_type: Type of vulnerability (e.g., "reentrancy", "timestamp-dependence", "assembly")
        finding_description: Full description of the finding from the analysis tool
        code_context: Relevant code snippet or file path where the finding occurs (optional but recommended)
        tool_source: Source tool that generated the finding (e.g., "slither", "mythril", "securify")
    
    Returns:
        str: JSON-formatted validation result with:
        - is_valid: bool - Whether this is a genuine vulnerability
        - confidence: float - Confidence level (0.0-1.0)
        - reasoning: str - Explanation of why it's valid or a false positive
        - false_positive_pattern: str - If false positive, which pattern matched
        - recommendations: list - Suggested actions
    
    Examples:
        validate_finding(
            "reentrancy",
            "Reentrancy in _accrueInterest()",
            "function _accrueInterest() { ... }",
            "slither"
        )
    """
    
    # Known false positive patterns for common tools
    false_positive_patterns = {
        "slither": {
            "reentrancy": [
                r"external call.*before.*state.*update",
                r"reentrancy.*interest.*accrual",
                r"reentrancy.*view.*function",
                r"reentrancy.*pure.*function",
            ],
            "timestamp-dependence": [
                r"block\.timestamp.*==.*0",
                r"elapsed.*==.*0",
                r"timestamp.*equality.*check",
            ],
            "assembly": [
                r"assembly.*storage.*read",
                r"assembly.*extSloads",
                r"assembly.*optimization",
            ],
            "low-level-calls": [
                r"safeTransfer.*call",
                r"safeTransferFrom.*call",
                r"transfer.*library",
            ],
        },
        "mythril": {
            "reentrancy": [
                r"external.*call.*before.*state",
            ],
            "timestamp": [
                r"block\.timestamp.*==.*0",
            ],
        },
    }
    
    # Common noise patterns that are almost always false positives
    noise_patterns = [
        r"naming.*convention",
        r"code.*style",
        r"informational",
        r"optimization",
        r"gas.*optimization",
        r"unused.*variable",
        r"missing.*documentation",
    ]
    
    result = {
        "is_valid": True,
        "confidence": 0.5,
        "reasoning": "",
        "false_positive_pattern": None,
        "recommendations": []
    }
    
    finding_lower = finding_description.lower()
    finding_type_lower = finding_type.lower()
    
    # Check for noise patterns first
    for pattern in noise_patterns:
        if re.search(pattern, finding_lower, re.IGNORECASE):
            result["is_valid"] = False
            result["confidence"] = 0.9
            result["reasoning"] = f"Finding matches noise pattern: '{pattern}'. This is likely informational or style-related, not a security vulnerability."
            result["false_positive_pattern"] = f"noise:{pattern}"
            result["recommendations"].append("Filter out informational/style findings from security reports")
            return json.dumps(result, indent=2)
    
    # Check tool-specific false positive patterns
    if tool_source.lower() in false_positive_patterns:
        tool_patterns = false_positive_patterns[tool_source.lower()]
        
        if finding_type_lower in tool_patterns:
            for pattern in tool_patterns[finding_type_lower]:
                if re.search(pattern, finding_lower, re.IGNORECASE):
                    result["is_valid"] = False
                    result["confidence"] = 0.85
                    result["reasoning"] = (
                        f"Finding matches known false positive pattern for {tool_source}: '{pattern}'. "
                        f"Common false positives for {finding_type} include cases where: "
                        f"(1) The code pattern is safe by design, (2) The tool misinterprets control flow, "
                        f"or (3) The finding is in library code with proper safeguards."
                    )
                    result["false_positive_pattern"] = f"{tool_source}:{pattern}"
                    result["recommendations"].extend([
                        "Review the actual code context to confirm exploitability",
                        "Check if there are existing safeguards (e.g., reentrancy guards, access controls)",
                        "Verify if this is in library code that's already audited"
                    ])
                    return json.dumps(result, indent=2)
    
    # Context-based validation
    if code_context:
        code_lower = code_context.lower()
        
        # Check for common safe patterns
        safe_patterns = {
            "reentrancy": [
                r"nonReentrant",
                r"ReentrancyGuard",
                r"checks.*effects.*interactions",
            ],
            "timestamp": [
                r"block\.number",
                r"oracle",
                r"time.*window",
            ],
        }
        
        if finding_type_lower in safe_patterns:
            for pattern in safe_patterns[finding_type_lower]:
                if re.search(pattern, code_lower, re.IGNORECASE):
                    result["is_valid"] = False
                    result["confidence"] = 0.8
                    result["reasoning"] = (
                        f"Code context shows safe pattern '{pattern}' is present. "
                        f"This suggests the finding may be a false positive due to existing safeguards."
                    )
                    result["false_positive_pattern"] = f"safe_pattern:{pattern}"
                    result["recommendations"].append("Verify that safeguards are correctly implemented and active")
                    return json.dumps(result, indent=2)
    
    # If we get here, it might be valid - but need more context
    if not code_context:
        result["confidence"] = 0.3
        result["reasoning"] = (
            "Cannot definitively validate without code context. "
            "Please provide the actual code snippet where this finding occurs."
        )
        result["recommendations"].append("Provide code context for more accurate validation")
    else:
        result["confidence"] = 0.6
        result["reasoning"] = (
            "Finding does not match known false positive patterns. "
            "However, manual review is recommended to confirm exploitability."
        )
        result["recommendations"].extend([
            "Manually review the code to confirm exploitability",
            "Check if there are test cases that demonstrate the vulnerability",
            "Consider running additional tools (e.g., fuzzing) to validate"
        ])
    
    return json.dumps(result, indent=2)


@function_tool
def filter_false_positives(
    findings_json: str,
    tool_source: str = "slither",
    min_confidence: float = 0.5
) -> str:
    """
    Filter false positives from a batch of security findings.
    
    Takes a JSON array of findings and validates each one, returning only
    those that pass validation thresholds.
    
    Args:
        findings_json: JSON string containing array of findings, each with:
            - type: str - Vulnerability type
            - description: str - Finding description
            - location: str (optional) - Code location
            - severity: str (optional) - Severity level
        tool_source: Source tool that generated findings
        min_confidence: Minimum confidence threshold (0.0-1.0) to include finding
    
    Returns:
        str: JSON object with:
        - total_findings: int - Original count
        - valid_findings: int - Count after filtering
        - filtered_findings: list - Valid findings with validation metadata
        - false_positives: list - Filtered out findings with reasons
    """
    
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({
            "error": "Invalid JSON format",
            "total_findings": 0,
            "valid_findings": 0,
            "filtered_findings": [],
            "false_positives": []
        }, indent=2)
    
    if not isinstance(findings, list):
        return json.dumps({
            "error": "Findings must be a JSON array",
            "total_findings": 0,
            "valid_findings": 0,
            "filtered_findings": [],
            "false_positives": []
        }, indent=2)
    
    valid_findings = []
    false_positives = []
    
    for finding in findings:
        finding_type = finding.get("type", finding.get("vulnerability_type", "unknown"))
        description = finding.get("description", finding.get("message", ""))
        location = finding.get("location", finding.get("code_context", ""))
        
        # Validate the finding
        validation_result = json.loads(validate_finding(
            finding_type=finding_type,
            finding_description=description,
            code_context=location,
            tool_source=tool_source
        ))
        
        if validation_result["is_valid"] and validation_result["confidence"] >= min_confidence:
            finding["validation"] = validation_result
            valid_findings.append(finding)
        else:
            false_positives.append({
                "finding": finding,
                "validation": validation_result,
                "reason": validation_result["reasoning"]
            })
    
    return json.dumps({
        "total_findings": len(findings),
        "valid_findings": len(valid_findings),
        "filtered_findings": valid_findings,
        "false_positives": false_positives,
        "filter_rate": f"{(len(false_positives)/len(findings)*100):.1f}%" if findings else "0%"
    }, indent=2)


def _extract_field(obj, keys):
    for key in keys:
        if isinstance(obj, dict) and key in obj and obj[key] not in [None, ""]:
            return obj[key]
    return None


def _stringify_field(value) -> str:
    if isinstance(value, list):
        return " ".join([str(v) for v in value if v is not None])
    return "" if value is None else str(value)


def _looks_permissionless(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    allow_markers = [
        "permissionless",
        "public caller",
        "anyone can",
        "no auth",
        "unauthenticated",
    ]
    return any(marker in lowered for marker in allow_markers)


def _looks_privileged(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    privileged_markers = [
        "admin",
        "onlyadmin",
        "owner",
        "onlyowner",
        "governance",
        "multisig",
        "timelock",
        "operator",
        "privileged",
        "insider",
        "oracle",
        "keeper",
        "relayer",
    ]
    return any(marker in lowered for marker in privileged_markers)


def _normalize_findings(raw):
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ["findings", "items", "issues", "results"]:
            if key in raw and isinstance(raw[key], list):
                return raw[key]
    return []


@function_tool
def council_filter_findings(
    findings_json: str,
    require_permissionless: bool = True,
    require_signal_fields: bool = True
) -> str:
    """
    Council-based false positive filter anchored to Signal/Karen Council rules.

    Enforces permissionless-only findings and strict evidence requirements.
    Findings missing required evidence are bucketed as NEEDS_EVIDENCE.
    """
    try:
        payload = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({
            "error": "Invalid JSON format",
            "validated": [],
            "needs_evidence": [],
            "rejected": [],
        }, indent=2)

    findings = _normalize_findings(payload)
    if not findings:
        return json.dumps({
            "error": "Findings must be a JSON array or contain 'findings' list",
            "validated": [],
            "needs_evidence": [],
            "rejected": [],
        }, indent=2)

    required_fields = [
        "target_asset",
        "vulnerability_class",
        "exact_endpoint_or_component",
        "preconditions",
        "reproduction_steps",
        "expected_vs_observed",
        "impact_statement",
        "proof_artifacts",
    ]

    validated = []
    needs_evidence = []
    rejected = []

    for finding in findings:
        if not isinstance(finding, dict):
            rejected.append({
                "finding": finding,
                "reason": "Invalid finding format (expected object).",
            })
            continue

        evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
        claim = finding.get("claim", {}) if isinstance(finding.get("claim"), dict) else {}
        signal_claim = {}
        if isinstance(finding.get("signal_council"), dict):
            signal_claim = finding["signal_council"].get("claim", {}) or {}

        # Permissionless gate
        permissionless_flag = finding.get("permissionless", None)
        preconditions_text = _stringify_field(_extract_field(
            finding, ["preconditions", "attack_requirements", "access"]
        ))
        permissionless_signal = _looks_permissionless(preconditions_text)

        if require_permissionless:
            if permissionless_flag is False:
                rejected.append({
                    "finding": finding,
                    "reason": "Not permissionless (explicit flag).",
                })
                continue
            if permissionless_flag is None and _looks_privileged(preconditions_text):
                rejected.append({
                    "finding": finding,
                    "reason": "Not permissionless (privileged access indicated).",
                })
                continue
            if permissionless_flag is None and not permissionless_signal:
                needs_evidence.append({
                    "finding": finding,
                    "reason": "Permissionless access not demonstrated.",
                })
                continue

        # Council verdict gates if provided
        karen_status = ""
        signal_status = ""
        if isinstance(finding.get("karen_council"), dict):
            karen_status = str(finding["karen_council"].get("status", "")).upper()
        if isinstance(finding.get("signal_council"), dict):
            signal_status = str(finding["signal_council"].get("status", "")).upper()

        if karen_status in ["DISPROVED", "FALSE-POSITIVE", "FALSE_POSITIVE"]:
            rejected.append({"finding": finding, "reason": "Karen Council disproved."})
            continue
        if signal_status in ["OUT_OF_SCOPE", "DUPLICATE_SUSPECTED", "NOT_A_VULN", "LOW_IMPACT", "UNREPRODUCIBLE"]:
            rejected.append({"finding": finding, "reason": "Signal Council rejected."})
            continue
        if signal_status in ["PENDING_EVIDENCE", "NEEDS_MORE_DATA"]:
            needs_evidence.append({"finding": finding, "reason": "Signal Council needs evidence."})
            continue

        # Evidence requirements
        missing_fields = []
        for field in required_fields:
            value = _extract_field(finding, [field])
            if value is None:
                value = _extract_field(evidence, [field])
            if value is None:
                value = _extract_field(claim, [field])
            if value is None:
                value = _extract_field(signal_claim, [field])

            if value is None or (isinstance(value, (list, str)) and len(value) == 0):
                missing_fields.append(field)

        if missing_fields and require_signal_fields:
            needs_evidence.append({
                "finding": finding,
                "reason": f"Missing required evidence fields: {', '.join(missing_fields)}",
                "missing_fields": missing_fields,
            })
            continue

        validated.append(finding)

    return json.dumps({
        "total_findings": len(findings),
        "validated": validated,
        "needs_evidence": needs_evidence,
        "rejected": rejected,
        "summary": {
            "validated": len(validated),
            "needs_evidence": len(needs_evidence),
            "rejected": len(rejected),
        }
    }, indent=2)
