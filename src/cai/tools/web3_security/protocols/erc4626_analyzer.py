"""
ERC-4626 Vault Analyzer

Specialized analyzer for ERC-4626 Tokenized Vault Standard contracts.
Detects:
- First depositor attacks (shares minted before any deposits)
- Share inflation attacks (share value decreases with each deposit)
- Rounding errors (precision loss in share calculations)

Based on exploit_db.jsonl patterns for ERC-4626 vulnerabilities.
"""

import json
import re
from typing import Any, Dict, List
from cai.sdk.agents import function_tool


# ERC-4626 specific vulnerability patterns
ERC4626_PATTERNS = {
    "first_depositor": {
        "code_signatures": ["convertToAssets", "convertToShares", "totalAssets", "totalShares"],
        "exploit_description": "First depositor can mint arbitrary share value by being the first to deposit when totalAssets=0",
        "negative_patterns": ["require(totalShares > 0)", "use initial deposit or virtual shares"],
        "test_assertion": "require(firstMintShares >= amount / 2)",
    },
    "share_inflation": {
        "code_signatures": ["totalSupply", "convertToAssets", "convertToShares"],
        "exploit_description": "Share price decreases with each withdraw due to rounding down of share value (share = floor(assets * shares / totalShares))",
        "negative_patterns": ["use math to compute shares correctly", "avoid floor operations", "add one wei to prevent rounding"],
        "test_assertion": "require(convertToAssets(user, amount) >= convertToAssets(user, amount) * (totalSupply + 1) / totalSupply) - 1e18)",
    },
    "rounding_errors": {
        "code_signatures": ["convertToAssets", "convertToShares", "/", "*"],
        "exploit_description": "Rounding down from share calculations (floor) causes value loss",
        "negative_patterns": ["use full precision (1e18 decimals)", "avoid division before multiplication", "use math library for rounding"],
        "test_assertion": "assert share value precision is maintained",
    },
}


def _extract_function_calls(
    code: str,
    pattern_name: str
) -> List[Dict[str, Any]]:
    """Extract function calls matching a vulnerability pattern."""
    findings = []
    
    pattern = ERC4626_PATTERNS.get(pattern_name)
    if not pattern:
        return findings
    
    for sig in pattern["code_signatures"]:
        if re.search(rf'\b{sig}\s*\([^)]*\)', code):
            # Extract function calls
            call_pattern = rf'\b{sig}\s*\([^)]*\)'
            matches = re.findall(call_pattern, code)
            
            for match in matches:
                # Extract function name and parameters
                func_match = re.match(rf'\b{sig}\s*\(\w+)', match)
                if func_match:
                    func_name = func_match.group(1)
                    params_str = match.group(2)
                    # Extract parameters
                    params = re.findall(r'(\w+,?\s*\)', params_str)
                    
                    findings.append({
                        "function": func_name,
                        "parameters": params,
                        "pattern_matched": pattern_name,
                        "severity": "HIGH",
                    })
    
    return findings


def _check_negative_patterns(
    code: str,
    pattern_name: str
) -> Dict[str, Any]:
    """
    Check for presence of negative protective patterns.
    
    Returns analysis of whether negative patterns exist.
    """
    pattern = ERC4626_PATTERNS.get(pattern_name)
    if not pattern:
        return {"pattern": pattern_name, "found": False, "missing_patterns": []}
    
    found_negative = []
    missing_negative = []
    
    # Check each negative pattern
    for neg_pattern in pattern["negative_patterns"]:
        if neg_pattern == "require(totalShares > 0)":
            if "require" in code and "totalShares" in code and "> 0" not in code:
                found_negative.append("Missing totalShares > 0 check")
            else:
                missing_negative.append("Has require(totalShares > 0) check")
        
        elif neg_pattern == "use math to compute shares correctly":
            math_patterns = ["1e18", "RAY", "Math.max", "floor"]
            if any(pattern in code for pattern in math_patterns):
                found_negative.append(f"Uses math operations: {pattern}")
        
        elif neg_pattern == "add one wei to prevent rounding":
            if "1e18" in code or "1 wei" in code:
                found_negative.append("Adds 1 wei for rounding protection")
        
        elif neg_pattern == "use full precision (1e18 decimals)":
            if "1e18" in code:
                found_negative.append("Uses full precision")
        
        elif neg_pattern == "avoid floor operations":
            if "/" in code and "*" in code and "floor(" in code:
                found_negative.append("Has floor() operation - vulnerable to rounding")
    
    return {
        "pattern": pattern_name,
        "found": len(found_negative) > 0 or len(missing_negative) > 0,
        "negative_patterns_present": found_negative,
        "negative_patterns_missing": missing_negative,
        "mitigation_recommendations": [
            f"Add {neg_pattern} check if not present",
            f"Implement share calculation with full precision",
            f"Use RAY = Math.max(0, x, y) for max/min",
        ],
    }


@function_tool
def analyze_erc4626_vault(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze ERC-4626 Vault contract for specific vulnerabilities.
    
    Detects:
    - First depositor attacks
    - Share inflation attacks
    - Rounding errors
    
    Returns:
        JSON with vulnerability analysis
    """
    try:
        findings = []
        
        # Check for ERC-4626 indicators
        is_vault = False
        has_deposit = False
        has_withdraw = False
        has_convert = False
        
        code_lower = contract_code.lower()
        
        if "deposit" in code_lower and "converttoassets" in code_lower:
            is_vault = True
            has_deposit = True
        if "converttoshares" in code_lower:
                has_convert = True
        
        if "withdraw" in code_lower or "redeem" in code_lower:
            has_withdraw = True
        
        # Analyze first depositor vulnerability
        if "converttoassets" in code_lower and "totalshares" in code_lower and "totalassets" not in code_lower:
            findings.append({
                "type": "first_depositor",
                "severity": "CRITICAL",
                "description": "convertToAssets called without totalAssets > 0 check - first depositor attack vulnerability",
                "location": "convertToAssets function",
                "recommendation": "Add require(totalShares > 0) validation or use virtual shares for initial deposits",
                "negative_patterns_missing": _check_negative_patterns(contract_code, "first_depositor").get("missing_negative_patterns", []),
            })
        
        # Analyze share inflation
        if "totalshares" in code_lower:
            calls = _extract_function_calls(contract_code, "share_inflation")
            
            if calls:
                findings.extend(calls)
                findings.append({
                    "type": "share_inflation",
                    "severity": "HIGH",
                    "description": "Potential share inflation - convertToShares uses floor division",
                    "functions": calls,
                })
        
        # Analyze rounding errors
        if "/" in code_lower or "*" in code.lower():
            findings.append({
                "type": "rounding_error",
                "severity": "MEDIUM",
                "description": "Division or multiplication before multiplication causes rounding down (share = floor(assets * shares / totalShares))",
                "recommendation": "Use full precision and RAY = Math.max(0, x, y)",
                "negative_patterns_missing": _check_negative_patterns(contract_code, "rounding_errors").get("negative_patterns_missing", []),
            })
        
        # Check for protective measures
        protective_checks = _check_negative_patterns(contract_code, "erc4626_protections").get("negative_patterns_present", [])
        
        return json.dumps({
            "contract_type": "erc4626_vault",
            "vulnerability_detected": is_vault,
            "has_first_depositor_check": has_deposit,
            "has_withdraw_check": has_withdraw,
            "has_convert_check": has_convert,
            "findings": findings,
            "protective_measures": protective_checks,
            "recommendations": [
                "Add totalAssets > 0 check before deposit operations",
                "Implement share calculation with full precision (1e18)",
                "Use RAY = Math.max for max/min comparisons",
                "Verify share price never decreases except for legitimate withdrawals",
            ],
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Error analyzing ERC-4626 vault: {str(e)}"})


class ERC4626Analyzer:
    """Simple wrapper class for ERC-4626 vault analysis."""

    def analyze(self, contract_code: str) -> Dict[str, Any]:
        return json.loads(analyze_erc4626_vault(contract_code))