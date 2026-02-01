"""
Finding Validation and False Positive Filtering

This module provides tools for validating security findings and filtering
out false positives through cross-tool correlation and heuristic analysis.
"""

import json
import re
from typing import Any, Dict, List, Optional
from cai.sdk.agents import function_tool


# Known false positive patterns
FALSE_POSITIVE_PATTERNS = {
    "reentrancy-benign": {
        "conditions": [
            "view_function",
            "pure_function",
            "no_state_change_after_call",
            "internal_call_only",
        ],
        "confidence_reduction": 0.8,
    },
    "unused-return": {
        "conditions": [
            "intentional_ignore",
            "try_catch_handled",
            "known_safe_function",
        ],
        "confidence_reduction": 0.6,
    },
    "low-level-calls": {
        "conditions": [
            "return_checked",
            "assembly_optimized",
            "known_pattern",
        ],
        "confidence_reduction": 0.5,
    },
    "arbitrary-send-eth": {
        "conditions": [
            "owner_only",
            "access_controlled",
            "withdrawal_pattern",
        ],
        "confidence_reduction": 0.7,
    },
}

# Tool reliability scores for cross-validation
TOOL_RELIABILITY = {
    "slither": {"precision": 0.7, "recall": 0.9, "strengths": ["reentrancy", "access-control"]},
    "mythril": {"precision": 0.8, "recall": 0.6, "strengths": ["integer-overflow", "delegatecall"]},
    "echidna": {"precision": 0.9, "recall": 0.5, "strengths": ["invariant-violation", "assertion"]},
    "medusa": {"precision": 0.85, "recall": 0.55, "strengths": ["property-testing", "fuzzing"]},
    "certora": {"precision": 0.95, "recall": 0.4, "strengths": ["formal-verification", "invariants"]},
}


def _check_false_positive_conditions(finding: Dict, code: str) -> List[str]:
    """Check which false positive conditions apply to a finding."""
    matched_conditions = []
    finding_type = finding.get("type", finding.get("check", "")).lower()
    
    # Check for view/pure functions
    if "view" in code.lower() or "pure" in code.lower():
        matched_conditions.append("view_function")
    
    # Check for access control
    access_patterns = [r"onlyOwner", r"onlyAdmin", r"require\(msg\.sender\s*==", r"modifier\s+only"]
    for pattern in access_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            matched_conditions.append("access_controlled")
            matched_conditions.append("owner_only")
            break
    
    # Check for return value handling
    if re.search(r"require\([^)]*\.call", code) or re.search(r"if\s*\([^)]*\.call", code):
        matched_conditions.append("return_checked")
    
    # Check for try-catch
    if "try" in code.lower() and "catch" in code.lower():
        matched_conditions.append("try_catch_handled")
    
    # Check for withdrawal pattern
    if re.search(r"withdraw|claim|transfer.*msg\.sender", code, re.IGNORECASE):
        matched_conditions.append("withdrawal_pattern")
    
    return list(set(matched_conditions))


@function_tool
def validate_finding(
    finding: str,
    contract_code: str = "",
    additional_context: str = "",
    ctf=None
) -> str:
    """
    Validate a single vulnerability finding.
    
    Analyzes the finding against known false positive patterns and
    provides a confidence-adjusted assessment.
    
    Args:
        finding: JSON string of the vulnerability finding
        contract_code: Relevant contract source code for context
        additional_context: Additional context about the finding
    
    Returns:
        JSON string with validation results including:
        - Adjusted confidence
        - False positive likelihood
        - Validation reasoning
    """
    try:
        finding_data = json.loads(finding) if isinstance(finding, str) else finding
        
        finding_type = finding_data.get("type", finding_data.get("check", "unknown")).lower()
        original_confidence = finding_data.get("confidence", 0.7)
        
        if isinstance(original_confidence, str):
            confidence_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
            original_confidence = confidence_map.get(original_confidence.lower(), 0.6)
        
        # Check for false positive conditions
        matched_conditions = []
        confidence_reduction = 0
        
        if contract_code:
            matched_conditions = _check_false_positive_conditions(finding_data, contract_code)
        
        # Apply false positive pattern matching
        for pattern_type, pattern_info in FALSE_POSITIVE_PATTERNS.items():
            if pattern_type in finding_type:
                matching_fp_conditions = [c for c in pattern_info["conditions"] if c in matched_conditions]
                if matching_fp_conditions:
                    confidence_reduction = max(confidence_reduction, 
                                               pattern_info["confidence_reduction"] * len(matching_fp_conditions) / len(pattern_info["conditions"]))
        
        # Calculate adjusted confidence
        adjusted_confidence = original_confidence * (1 - confidence_reduction)
        
        # Determine false positive likelihood
        if confidence_reduction > 0.5:
            fp_likelihood = "HIGH"
        elif confidence_reduction > 0.2:
            fp_likelihood = "MEDIUM"
        else:
            fp_likelihood = "LOW"
        
        # Generate reasoning
        reasoning = []
        if matched_conditions:
            reasoning.append(f"Detected patterns: {', '.join(matched_conditions)}")
        if confidence_reduction > 0:
            reasoning.append(f"Confidence reduced by {confidence_reduction:.0%} due to false positive indicators")
        if not reasoning:
            reasoning.append("No false positive indicators detected")
        
        # Recommendation
        if fp_likelihood == "HIGH":
            recommendation = "LIKELY_FALSE_POSITIVE - Manual review recommended before reporting"
        elif fp_likelihood == "MEDIUM":
            recommendation = "NEEDS_VERIFICATION - Additional analysis recommended"
        else:
            recommendation = "LIKELY_VALID - Proceed with standard reporting"
        
        return json.dumps({
            "original_confidence": original_confidence,
            "adjusted_confidence": round(adjusted_confidence, 3),
            "confidence_reduction": round(confidence_reduction, 3),
            "false_positive_likelihood": fp_likelihood,
            "matched_conditions": matched_conditions,
            "reasoning": reasoning,
            "recommendation": recommendation,
            "validated_finding": {
                **finding_data,
                "validated_confidence": round(adjusted_confidence, 3),
                "validation_status": recommendation.split(" - ")[0],
            },
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error validating finding: {str(e)}"})


@function_tool
def filter_false_positives(
    findings: str,
    contract_code: str = "",
    threshold: float = 0.3,
    ctf=None
) -> str:
    """
    Filter out likely false positives from a list of findings.
    
    Args:
        findings: JSON string of vulnerability findings array
        contract_code: Contract source code for context
        threshold: Minimum adjusted confidence to keep (default: 0.3)
    
    Returns:
        JSON string with filtered findings and statistics
    """
    try:
        findings_list = json.loads(findings) if isinstance(findings, str) else findings
        
        if not isinstance(findings_list, list):
            findings_list = [findings_list]
        
        validated_findings = []
        filtered_out = []
        
        for finding in findings_list:
            validation_result = validate_finding(
                json.dumps(finding),
                contract_code=contract_code
            )
            validation_data = json.loads(validation_result)
            
            if "error" in validation_data:
                # Keep findings that couldn't be validated
                validated_findings.append(finding)
                continue
            
            adjusted_confidence = validation_data.get("adjusted_confidence", 0.5)
            
            if adjusted_confidence >= threshold:
                validated_findings.append({
                    **finding,
                    "validated_confidence": adjusted_confidence,
                    "fp_likelihood": validation_data["false_positive_likelihood"],
                })
            else:
                filtered_out.append({
                    "finding": finding,
                    "reason": validation_data["reasoning"],
                    "adjusted_confidence": adjusted_confidence,
                })
        
        return json.dumps({
            "filtered_findings": validated_findings,
            "filtered_out": filtered_out,
            "statistics": {
                "original_count": len(findings_list),
                "remaining_count": len(validated_findings),
                "filtered_count": len(filtered_out),
                "filter_rate": round(len(filtered_out) / max(len(findings_list), 1), 3),
            },
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error filtering false positives: {str(e)}"})


@function_tool
def cross_validate_findings(
    findings_by_tool: str,
    ctf=None
) -> str:
    """
    Cross-validate findings from multiple security tools.
    
    Findings reported by multiple tools are given higher confidence,
    while tool-specific findings are weighted by tool reliability.
    
    Args:
        findings_by_tool: JSON string with findings grouped by tool.
                          Format: {"slither": [...], "mythril": [...], ...}
    
    Returns:
        JSON string with cross-validated findings and confidence scores
    """
    try:
        tool_findings = json.loads(findings_by_tool) if isinstance(findings_by_tool, str) else findings_by_tool
        
        # Normalize and group findings by type/location
        finding_groups = {}
        
        for tool, findings in tool_findings.items():
            tool_reliability = TOOL_RELIABILITY.get(tool.lower(), {"precision": 0.5, "recall": 0.5, "strengths": []})
            
            for finding in findings:
                # Create a key for grouping similar findings
                finding_type = finding.get("type", finding.get("check", "unknown")).lower()
                location = finding.get("location", {})
                contract = location.get("contract", finding.get("contract", ""))
                function = location.get("function", finding.get("function", ""))
                
                key = f"{finding_type}:{contract}:{function}"
                
                if key not in finding_groups:
                    finding_groups[key] = {
                        "type": finding_type,
                        "contract": contract,
                        "function": function,
                        "tools": [],
                        "findings": [],
                    }
                
                finding_groups[key]["tools"].append(tool)
                finding_groups[key]["findings"].append({
                    "tool": tool,
                    "finding": finding,
                    "tool_precision": tool_reliability["precision"],
                })
        
        # Calculate cross-validated confidence
        validated_findings = []
        
        for key, group in finding_groups.items():
            num_tools = len(set(group["tools"]))
            
            # Base confidence from tool agreement
            if num_tools >= 3:
                agreement_bonus = 0.3
            elif num_tools == 2:
                agreement_bonus = 0.15
            else:
                agreement_bonus = 0
            
            # Average tool precision
            avg_precision = sum(f["tool_precision"] for f in group["findings"]) / len(group["findings"])
            
            # Check if finding type matches tool strengths
            strength_bonus = 0
            for f in group["findings"]:
                tool = f["tool"].lower()
                if tool in TOOL_RELIABILITY:
                    if any(s in group["type"] for s in TOOL_RELIABILITY[tool]["strengths"]):
                        strength_bonus = max(strength_bonus, 0.1)
            
            # Calculate final confidence
            cross_validated_confidence = min(1.0, avg_precision + agreement_bonus + strength_bonus)
            
            # Determine severity (use highest from any tool)
            severities = [f["finding"].get("severity", "medium") for f in group["findings"]]
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            max_severity = max(severities, key=lambda s: severity_order.get(s.lower(), 2))
            
            validated_findings.append({
                "type": group["type"],
                "contract": group["contract"],
                "function": group["function"],
                "severity": max_severity,
                "cross_validated_confidence": round(cross_validated_confidence, 3),
                "reported_by_tools": list(set(group["tools"])),
                "tool_count": num_tools,
                "agreement_level": "HIGH" if num_tools >= 3 else "MEDIUM" if num_tools == 2 else "LOW",
                "original_findings": group["findings"],
            })
        
        # Sort by confidence
        validated_findings.sort(key=lambda x: x["cross_validated_confidence"], reverse=True)
        
        return json.dumps({
            "cross_validated_findings": validated_findings,
            "statistics": {
                "total_unique_findings": len(validated_findings),
                "high_agreement_count": sum(1 for f in validated_findings if f["agreement_level"] == "HIGH"),
                "medium_agreement_count": sum(1 for f in validated_findings if f["agreement_level"] == "MEDIUM"),
                "single_tool_count": sum(1 for f in validated_findings if f["agreement_level"] == "LOW"),
            },
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error cross-validating findings: {str(e)}"})
