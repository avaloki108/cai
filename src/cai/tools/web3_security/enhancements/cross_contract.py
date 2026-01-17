"""
Cross-Contract Analysis Tool

This module analyzes interactions between contracts to identify:
- Cross-contract call patterns
- Economic invariant assumptions
- Potential cross-contract exploit vectors
"""

import json
import re
from typing import Any, Dict, List, Optional
from cai.sdk.agents import function_tool


# Common patterns indicating external interactions
EXTERNAL_CALL_PATTERNS = [
    r"\.call\s*\(",
    r"\.delegatecall\s*\(",
    r"\.staticcall\s*\(",
    r"\.transfer\s*\(",
    r"\.send\s*\(",
    r"IERC20\s*\(",
    r"SafeERC20\.",
    r"safeTransfer",
    r"safeTransferFrom",
    r"IUniswap",
    r"IAave",
    r"ICompound",
    r"IChainlink",
    r"priceFeed\.",
    r"oracle\.",
]

# Common economic invariant patterns
INVARIANT_PATTERNS = {
    "token_balance_tracking": {
        "patterns": [r"balanceOf\s*\(", r"totalSupply", r"_balances\["],
        "description": "Contract tracks token balances - verify internal accounting matches actual balances",
        "risk": "Balance desync can lead to fund extraction",
    },
    "share_accounting": {
        "patterns": [r"shares\[", r"totalShares", r"_shares\[", r"convertToShares", r"convertToAssets"],
        "description": "Share-based accounting (vault pattern) - precision loss and rounding attacks",
        "risk": "Share inflation/deflation attacks",
    },
    "price_oracle_dependency": {
        "patterns": [r"getPrice", r"latestAnswer", r"latestRoundData", r"price\s*="],
        "description": "Price oracle dependency - stale/manipulated prices",
        "risk": "Oracle manipulation via flash loans",
    },
    "collateral_ratio": {
        "patterns": [r"collateral", r"healthFactor", r"liquidat", r"isHealthy"],
        "description": "Collateralization requirements - liquidation logic",
        "risk": "Under-collateralization or liquidation cascade",
    },
    "access_control": {
        "patterns": [r"onlyOwner", r"require\s*\(\s*msg\.sender", r"hasRole", r"_checkRole"],
        "description": "Access control checks - authorization bypass",
        "risk": "Privilege escalation",
    },
    "reentrancy_guard": {
        "patterns": [r"nonReentrant", r"_status\s*=", r"locked\s*=", r"ReentrancyGuard"],
        "description": "Reentrancy protection - may be incomplete",
        "risk": "Cross-function or cross-contract reentrancy",
    },
    "deadline_check": {
        "patterns": [r"deadline", r"block\.timestamp", r"expiry", r"validUntil"],
        "description": "Timestamp-based deadlines - front-running window",
        "risk": "Transaction replay or timing attacks",
    },
}


def _extract_external_calls(code: str) -> List[Dict[str, Any]]:
    """Extract external call patterns from code."""
    calls = []
    lines = code.split("\n")
    
    for i, line in enumerate(lines):
        for pattern in EXTERNAL_CALL_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Try to extract function context
                func_match = re.search(r"function\s+(\w+)", "\n".join(lines[max(0, i-20):i+1]))
                func_name = func_match.group(1) if func_match else "unknown"
                
                calls.append({
                    "line": i + 1,
                    "pattern": pattern,
                    "code_snippet": line.strip(),
                    "function": func_name,
                })
    
    return calls


def _detect_invariants(code: str) -> List[Dict[str, Any]]:
    """Detect economic invariant patterns in code."""
    detected = []
    
    for invariant_name, invariant_info in INVARIANT_PATTERNS.items():
        for pattern in invariant_info["patterns"]:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                detected.append({
                    "type": invariant_name,
                    "matches": len(matches),
                    "description": invariant_info["description"],
                    "risk": invariant_info["risk"],
                    "sample_matches": matches[:5],
                })
                break  # Only add once per invariant type
    
    return detected


@function_tool
def analyze_contract_interactions(contracts: str, ctf=None) -> str:
    """
    Analyze interactions between multiple contracts.
    
    Maps external calls, identifies trust boundaries, and detects
    potential cross-contract exploit vectors.
    
    Args:
        contracts: JSON string with contract data. Format:
                   {"contract_name": "source_code", ...} or
                   [{"name": "...", "code": "..."}, ...]
    
    Returns:
        JSON string with interaction analysis including:
        - External calls per contract
        - Trust boundaries
        - Potential attack surfaces
    
    Example:
        analyze_contract_interactions('{"Vault": "contract Vault {...}", "Token": "contract Token {...}"}')
    """
    try:
        if isinstance(contracts, str):
            contracts_data = json.loads(contracts)
        else:
            contracts_data = contracts
        
        # Normalize input format
        if isinstance(contracts_data, list):
            contracts_dict = {c.get("name", f"contract_{i}"): c.get("code", c.get("source", "")) 
                           for i, c in enumerate(contracts_data)}
        else:
            contracts_dict = contracts_data
        
        analysis = {
            "contracts": [],
            "cross_contract_calls": [],
            "trust_boundaries": [],
            "attack_surfaces": [],
        }
        
        # Analyze each contract
        for name, code in contracts_dict.items():
            if not code:
                continue
            
            external_calls = _extract_external_calls(code)
            invariants = _detect_invariants(code)
            
            contract_analysis = {
                "name": name,
                "external_calls_count": len(external_calls),
                "external_calls": external_calls[:10],  # Limit output
                "detected_invariants": invariants,
                "has_reentrancy_guard": any(i["type"] == "reentrancy_guard" for i in invariants),
                "has_access_control": any(i["type"] == "access_control" for i in invariants),
                "uses_oracle": any(i["type"] == "price_oracle_dependency" for i in invariants),
            }
            analysis["contracts"].append(contract_analysis)
            
            # Identify cross-contract references
            for other_name in contracts_dict.keys():
                if other_name != name and other_name in code:
                    analysis["cross_contract_calls"].append({
                        "from": name,
                        "to": other_name,
                        "pattern": "direct_reference",
                    })
        
        # Identify trust boundaries
        for contract in analysis["contracts"]:
            if contract["external_calls_count"] > 0 and not contract["has_reentrancy_guard"]:
                analysis["trust_boundaries"].append({
                    "contract": contract["name"],
                    "issue": "External calls without reentrancy protection",
                    "severity": "HIGH",
                })
            
            if contract["uses_oracle"]:
                analysis["trust_boundaries"].append({
                    "contract": contract["name"],
                    "issue": "Oracle dependency - potential manipulation vector",
                    "severity": "MEDIUM",
                })
        
        # Identify attack surfaces
        for contract in analysis["contracts"]:
            for invariant in contract["detected_invariants"]:
                if invariant["type"] in ["token_balance_tracking", "share_accounting"]:
                    analysis["attack_surfaces"].append({
                        "contract": contract["name"],
                        "type": invariant["type"],
                        "risk": invariant["risk"],
                        "recommendation": "Verify internal accounting matches actual state",
                    })
        
        # Summary
        analysis["summary"] = {
            "total_contracts": len(analysis["contracts"]),
            "total_external_calls": sum(c["external_calls_count"] for c in analysis["contracts"]),
            "contracts_without_reentrancy_guard": sum(1 for c in analysis["contracts"] if not c["has_reentrancy_guard"]),
            "oracle_dependent_contracts": sum(1 for c in analysis["contracts"] if c["uses_oracle"]),
            "high_risk_boundaries": len([t for t in analysis["trust_boundaries"] if t["severity"] == "HIGH"]),
        }
        
        return json.dumps(analysis, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to analyze contract interactions: {str(e)}",
            "contracts": [],
        })


@function_tool
def find_economic_invariants(protocol_code: str, protocol_type: str = "defi", ctf=None) -> str:
    """
    Identify economic invariants and assumptions in protocol code.
    
    Looks for patterns that indicate economic assumptions (balance tracking,
    price dependencies, collateral ratios) that could be violated.
    
    Args:
        protocol_code: Source code of the protocol (single file or concatenated).
        protocol_type: Type of protocol ("defi", "nft", "governance", "bridge").
    
    Returns:
        JSON string with identified invariants and their risk assessments.
    
    Example:
        find_economic_invariants(vault_code, protocol_type="defi")
    """
    try:
        invariants = _detect_invariants(protocol_code)
        
        # Additional protocol-specific analysis
        protocol_specific = []
        
        if protocol_type == "defi":
            # DeFi-specific patterns
            defi_patterns = {
                "flash_loan_risk": [r"flashLoan", r"executeOperation", r"onFlashLoan"],
                "amm_pattern": [r"swap\s*\(", r"getAmountOut", r"getReserves"],
                "lending_pattern": [r"borrow", r"repay", r"liquidate"],
                "yield_farming": [r"harvest", r"compound", r"stake", r"unstake"],
            }
            
            for pattern_name, patterns in defi_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, protocol_code, re.IGNORECASE):
                        protocol_specific.append({
                            "type": pattern_name,
                            "detected": True,
                            "risk": f"Protocol uses {pattern_name.replace('_', ' ')} - review for manipulation vectors",
                        })
                        break
        
        elif protocol_type == "governance":
            gov_patterns = {
                "vote_delegation": [r"delegate", r"getPriorVotes", r"getVotes"],
                "timelock": [r"timelock", r"delay", r"queueTransaction"],
                "proposal": [r"propose", r"execute", r"castVote"],
            }
            
            for pattern_name, patterns in gov_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, protocol_code, re.IGNORECASE):
                        protocol_specific.append({
                            "type": pattern_name,
                            "detected": True,
                            "risk": f"Governance feature {pattern_name.replace('_', ' ')} - check for flash loan attacks",
                        })
                        break
        
        elif protocol_type == "bridge":
            bridge_patterns = {
                "cross_chain_message": [r"receiveMessage", r"sendMessage", r"verifyProof"],
                "relayer_trust": [r"relayer", r"validator", r"attestation"],
            }
            
            for pattern_name, patterns in bridge_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, protocol_code, re.IGNORECASE):
                        protocol_specific.append({
                            "type": pattern_name,
                            "detected": True,
                            "risk": f"Bridge pattern {pattern_name.replace('_', ' ')} - critical trust assumption",
                        })
                        break
        
        # Risk ranking
        high_risk_invariants = []
        medium_risk_invariants = []
        low_risk_invariants = []
        
        for inv in invariants:
            if inv["type"] in ["token_balance_tracking", "collateral_ratio", "price_oracle_dependency"]:
                high_risk_invariants.append(inv)
            elif inv["type"] in ["share_accounting", "access_control"]:
                medium_risk_invariants.append(inv)
            else:
                low_risk_invariants.append(inv)
        
        return json.dumps({
            "invariants": invariants,
            "protocol_specific": protocol_specific,
            "risk_breakdown": {
                "high_risk": high_risk_invariants,
                "medium_risk": medium_risk_invariants,
                "low_risk": low_risk_invariants,
            },
            "recommendations": [
                "Verify all balance tracking matches actual token balances",
                "Check oracle price freshness and manipulation resistance",
                "Review share/asset conversion for precision loss",
                "Test liquidation paths under stress conditions",
                "Verify access control covers all sensitive functions",
            ] if invariants else ["No significant invariants detected - manual review recommended"],
        }, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to find economic invariants: {str(e)}",
            "invariants": [],
        })


@function_tool
def check_invariant_violations(findings: str, invariants: str, ctf=None) -> str:
    """
    Cross-reference vulnerability findings with identified invariants.
    
    Checks if any findings could lead to invariant violations, which
    often indicates exploitable vulnerabilities.
    
    Args:
        findings: JSON string of vulnerability findings.
        invariants: JSON string of identified invariants from find_economic_invariants().
    
    Returns:
        JSON string with potential invariant violations and their severity.
    
    Example:
        check_invariant_violations(slither_findings, economic_invariants)
    """
    try:
        if isinstance(findings, str):
            findings_list = json.loads(findings)
        else:
            findings_list = findings
        
        if isinstance(invariants, str):
            invariants_data = json.loads(invariants)
        else:
            invariants_data = invariants
        
        # Extract invariant types
        invariant_types = [inv.get("type", "") for inv in invariants_data.get("invariants", [])]
        
        # Mapping of finding types to invariants they could violate
        finding_to_invariant = {
            "reentrancy": ["token_balance_tracking", "share_accounting"],
            "arithmetic": ["token_balance_tracking", "share_accounting", "collateral_ratio"],
            "oracle": ["price_oracle_dependency", "collateral_ratio"],
            "access": ["access_control"],
            "unchecked": ["token_balance_tracking"],
            "delegatecall": ["access_control"],
            "uninitialized": ["access_control", "token_balance_tracking"],
        }
        
        violations = []
        
        for finding in findings_list if isinstance(findings_list, list) else [findings_list]:
            finding_type = finding.get("type", finding.get("check", "")).lower()
            
            for keyword, potentially_violated in finding_to_invariant.items():
                if keyword in finding_type:
                    for inv_type in potentially_violated:
                        if inv_type in invariant_types:
                            violations.append({
                                "finding": {
                                    "type": finding.get("type", finding.get("check")),
                                    "severity": finding.get("severity", "Unknown"),
                                    "location": finding.get("location", {}),
                                },
                                "violated_invariant": inv_type,
                                "exploitation_path": f"{finding_type} could violate {inv_type}",
                                "severity": "HIGH" if inv_type in ["token_balance_tracking", "price_oracle_dependency"] else "MEDIUM",
                            })
        
        # Deduplicate
        seen = set()
        unique_violations = []
        for v in violations:
            key = (str(v["finding"]["location"]), v["violated_invariant"])
            if key not in seen:
                seen.add(key)
                unique_violations.append(v)
        
        return json.dumps({
            "potential_violations": unique_violations,
            "total_violations": len(unique_violations),
            "high_severity_count": len([v for v in unique_violations if v["severity"] == "HIGH"]),
            "summary": {
                "findings_analyzed": len(findings_list) if isinstance(findings_list, list) else 1,
                "invariants_checked": len(invariant_types),
                "exploit_potential": "HIGH" if any(v["severity"] == "HIGH" for v in unique_violations) else "MEDIUM" if unique_violations else "LOW",
            },
        }, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to check invariant violations: {str(e)}",
            "potential_violations": [],
        })
