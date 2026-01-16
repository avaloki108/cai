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
