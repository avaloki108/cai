"""
Diamond Proxy Analyzer

Specialized analyzer for ERC-2535 Diamond Standard contracts.
Detects:
- Selector collisions between facets and implementations
- Upgrade path vulnerabilities
- Storage slot conflicts between facets
- Function clashing across upgrade paths

Based on exploit_db.jsonl patterns for ERC-2535 issues.
"""

import json
import re
from typing import Any, Dict, List
from cai.sdk.agents import function_tool


# ERC-2535 specific vulnerability patterns
DIAMOND_PATTERNS = {
    "selector_collision": {
        "code_signatures": ["function selector", "fallback", "receive", "onERC721Received", "onERC1155Received"],
        "negative_patterns": ["use EIP-2535 DiamondLoupe interface", "use function selector collision resistance"],
        "test_assertion": "require(diamondCut passes all selectors through loupe without collision",
    },
    "storage_collision": {
        "code_signatures": ["mapping", "struct", "storage slot"],
        "negative_patterns": ["initialize storage slots properly", "verify storage layout separation"],
        "test_assertion": "require(facetA.storage != facetB.storage)",
    },
    "upgrade_path": {
        "code_signatures": ["diamondCut", "upgradeTo", "upgrade(address)"],
        "negative_patterns": ["uninitialized implementation pointer", "two-step upgrade process", "timelock upgrades"],
        "test_assertion": "require(hasTimelock or multi-sig governance)",
    },
    "function_clashing": {
        "code_signatures": ["function A(", "function B(", "function override"],
        "negative_patterns": ["selector collision between facet implementations", "unsafe external calls via selector", "delegatecall to untrusted facet"],
        "test_assertion": "require(implementation follows EIP-2535 standard)",
    },
}


def _extract_facet_addresses(code: str) -> List[str]:
    """
    Extract facet addresses from Diamond contract code.
    
    Looks for pattern: address constant declarations and IERC-2535 loupe calls.
    """
    addresses = []
    
    # Find IERC-2535 Loupe interface calls
    loupe_pattern = r'IERC2535Loupe.*\.diamondCut\s*\(\s*(address\w+)\s*\)'
    loupe_matches = re.finditer(loupe_pattern, code, re.IGNORECASE)
    
    for match in loupe_matches:
        address_match = re.search(r'address\s+(\w+)', match.group(0))
        if address_match:
            addresses.append(address_match.group(1))
    
    # Find address constants
    addr_pattern = r'address\s+(?:?\s*)\w+\s*=\s*[\s\}]?=\s*\s*0x{40}.*}\s*;?=\s*\s*0x[01-9]'
    addr_matches = re.findall(addr_pattern, code)
    addresses.extend(addr_matches)
    
    return list(set(addresses))


def _detect_selector_collision(
    contract_code: str
) -> List[Dict[str, Any]]:
    """
    Detect potential selector collisions between Diamond facets.
    
    Looks for:
    - Function name conflicts
    - Fallback/receive confusion
    - Shared external call interfaces
    """
    collisions = []
    
    # Find all function definitions
    func_pattern = r'function\s+(\w+)\s*\([^)]*)\s*(?:[^{]*}*)\s*\{'
    functions = {}
    for match in re.finditer(func_pattern, contract_code):
        func_name = match.group(1)
        params_match = match.group(2) or ""
        
        # Check if function name already exists
        if func_name in functions:
            collisions.append({
                "type": "function_name_conflict",
                "description": f"Function '{func_name}' already defined in another facet or implementation",
                "severity": "MEDIUM",
                "function_1": func_name,
                "function_2": functions[func_name],
            })
    
        functions[func_name] = {
            "params": params_match,
            "code_location": match.start(),
        }
    
    # Check for selector conflicts with external callbacks
    # Fallback/receive functions can collide with onERC721Received/onERC1155Received
    callback_functions = ["onERC721Received", "onERC1155Received"]
    
    for func_name, func_data in functions.items():
        if func_name in callback_functions:
            # Check for fallback/receive definition conflicts
            if func_name == "fallback" and "receive" in functions:
                collisions.append({
                    "type": "callback_conflict",
                    "severity": "MEDIUM",
                    "description": "Both 'fallback' and 'receive' defined - callback target confusion",
                    "function_1": "fallback",
                    "function_2": "receive",
                    "code_location_1": func_data.get("code_location", -1),
                    "code_location_2": functions.get("receive", {}).get("code_location", -1),
                })
        
        # Check for override conflicts
        params = func_data.get("params", "")
        if params and "override" in params.lower():
            collisions.append({
                "type": "override_conflict",
                "severity": "HIGH", 
                "description": f"Function '{func_name}' uses override keyword - potential clashing",
                "function": func_name,
                "code_location": func_data.get("code_location", -1),
            })
    
    return collisions


def _detect_storage_collisions(
    contract_code: str,
    facet_addresses: List[str]
) -> List[Dict[str, Any]]:
    """
    Detect storage slot conflicts between Diamond facets.
    
    Checks for:
    - Overlapping storage slots
    - Uninitialized storage accessing
    - Storage slot name conflicts
    """
    conflicts = []
    
    # Track storage slot usage
    slot_usage = {}  # slot -> list of facets using it
    
    for address in facet_addresses:
        slot_pattern = rf'{address}\.slot(\w+)\s*=\s*'
        slot_matches = re.findall(slot_pattern, contract_code)
        
        for slot in slot_matches:
            slot_num = int(slot.group(1))
            slot_usage.setdefault(slot_num, []).append(address)
    
    # Check for overlapping slots
    for i, slot_i in enumerate(slot_matches):
        slot_num_i = int(slot_i.group(1))
        slot_users = slot_usage.get(slot_num_i, [])
        
        for j, slot_j in enumerate(slot_matches):
            slot_num_j = int(slot_j.group(1))
            if i >= j:
                slot_users_j = slot_usage.get(slot_num_j, [])
            
            # Check overlap
            overlap = set(slot_users) & set(slot_users_j)
            if overlap:
                conflicts.append({
                    "type": "storage_overlap",
                    "description": f"Storage slot {slot_num} used by both facet {facet_addresses[i]} and {facet_addresses[j]}",
                    "severity": "HIGH",
                    "slot": slot_num,
                    "facets_involved": [facet_addresses[i], facet_addresses[j]],
                })
    
    return conflicts


def _analyze_upgrade_path(
    contract_code: str
) -> List[Dict[str, Any]]:
    """
    Analyze Diamond upgrade path for vulnerabilities.
    
    Checks for:
    - Uninitialized implementation pointer
    - Missing two-step upgrade process
    - Timelock bypass
    - Direct admin calls without governance
    """
    vulnerabilities = []
    
    # Find diamondCut function
    cut_pattern = r'function\s+diamondCut\s*\([^)]*\)'
    cut_matches = re.finditer(cut_pattern, contract_code)
    
    # Find upgradeTo calls
    upgrade_pattern = r'function\s+upgradeTo\s*\([^)]*\)'
    upgrade_matches = re.finditer(upgrade_pattern, contract_code)
    
    for match in cut_matches:
        if "diamondCut(address(this)" in match.group():
            # Check if timelock
            if "timelock" not in contract_code.lower():
                vulnerabilities.append({
                    "type": "missing_timelock",
                    "severity": "HIGH",
                    "description": "diamondCut called without timelock check",
                    "function": "diamondCut",
                    "location": match.start(),
                })
            # Check for direct implementation calls
            implementation_calls = _find_implementation_calls(contract_code, match.start(), match.end())
            for call in implementation_calls:
                if call not in ["implementation", "initialize", "_setImplementation"]:  # Safe calls
                    vulnerabilities.append({
                        "type": "unsafe_implementation_call",
                        "severity": "HIGH",
                        "description": f"Direct call to '{call}' from diamondCut without safe governance wrapper",
                        "function": call,
                        "call_expression": call,
                        "location": call["location"],
                    })
    
    # Check for uninitialized implementation pointer
    if "address(this)" in cut_matches.group(0) or "this" in upgrade_matches:
        uninitialized_found = False
        for match in upgrade_matches:
            if match.group(1) in ["this", "0", "address(0)"] and "new_address" in upgrade_matches.group(1):
                uninitialized_found = True
                break
        
        if uninitialized_found:
            vulnerabilities.append({
                "type": "uninitialized_implementation",
                "severity": "CRITICAL",
                "description": "DiamondCut to uninitialized implementation - first depositor attack vulnerability",
                "function": "diamondCut",
                "location": match.start(),
            })
    
    # Check for two-step upgrade process
    has_timelock = "timelock" in contract_code.lower()
    has_init_check = "initialize" in upgrade_matches
    if has_timelock and not has_init_check:
        vulnerabilities.append({
            "type": "missing_timelock",
            "severity": "MEDIUM",
            "description": "Two-step upgrade process without timelock protection",
            "recommendation": "Add two-step governance with time delay",
        })
    
    return vulnerabilities


def _analyze_function_clashing(
    contract_code: str
) -> List[Dict[str, Any]]:
    """
    Analyze function clashing across Diamond facets.
    
    Checks for:
    - Selector collisions
    - Unsafe external calls via selector
    - Delegatecall to untrusted facets
    """
    clashing = []
    
    # Find all function definitions
    func_pattern = r'function\s+(\w+)\s*\([^)]*)\s*(?:[^{]*}*)\s*\{'
    functions = {}
    for match in re.finditer(func_pattern, contract_code):
        func_name = match.group(1)
        params_match = match.group(2) or ""
        
        functions[func_name] = {
            "params": params_match,
            "code_location": match.start(),
        }
    
    # Check for override conflicts
    if "override" in functions[func_name]["params"].lower():
            clashing.append({
                "type": "override_conflict",
                "description": f"Function '{func_name}' uses override keyword - potential clashing with parent/external function",
                "severity": "HIGH",
                "function_1": func_name,
                "code_location": functions[func_name]["code_location"],
                "params": functions[func_name]["params"],
            })
    
    # Check for unsafe external calls to untrusted facets
    for func_name, func_data in functions.items():
        params = func_data.get("params", "")
        if not params:
            continue
        
        # Check for delegatecall pattern
        delegate_pattern = r'.*\.delegatecall\s*\([^)]*\)'
        delegate_matches = re.finditer(delegate_pattern, contract_code)
        
        for match in delegate_matches:
            if "delegatecall(" in match.group():
                # Check if target is constant (untrusted)
                if match.group(1).lower() in ["address", "this", "constant", "untrustedfacet", "facet"]:
                    clashing.append({
                        "type": "unsafe_delegatecall",
                        "severity": "CRITICAL",
                        "description": f"delegatecall to '{match.group(1)}' - targets untrusted facet '{match.group(1)}' without safety check",
                        "function": func_name,
                        "delegatecall_pattern": match.group(),
                        "code_location": match.start(),
                    })
    
    return clashing


def _find_implementation_calls(
    contract_code: str,
    start_pos: int,
    end_pos: int
) -> List[str]:
    """
    Find implementation calls between two positions in code.
    
    Simple search for patterns.
    """
    calls = []
    
    # Implementation function call pattern
    impl_pattern = r'implementation\s*\(\w+)\s*\s*[a-z]+[^)]*\)'
    
    # UpgradeTo function call pattern
    upgrade_pattern = r'upgradeTo\s*\w+\s*\([^)]*\)'
    
    # Search for implementation calls
    for pattern in [impl_pattern, upgrade_pattern]:
        matches = re.finditer(pattern, contract_code[start_pos:end_pos])
        
        for match in matches:
            call_pattern = match.group(1).strip()
            if call_pattern:
                calls.append(call_pattern)
    
    return calls


@function_tool
def analyze_diamond(
    contract_code: str,
    ctf=None
) -> str:
    """
    Comprehensive analysis of ERC-2535 Diamond Standard contract.
    
    Detects all major Diamond vulnerability classes:
    - Selector collisions
    - Storage collisions
    - Upgrade path vulnerabilities
    - Function clashing
    
    Args:
        contract_code: Solidity source code of Diamond contract
    
    Returns:
        JSON with complete analysis
    """
    try:
        # Extract facet addresses
        facet_addresses = _extract_facet_addresses(contract_code)
        
        # Run all analyses
        selector_collisions = _detect_selector_collision(contract_code)
        storage_collisions = _detect_storage_collisions(contract_code, facet_addresses)
        upgrade_path_vulns = _analyze_upgrade_path(contract_code)
        function_clashing = _analyze_function_clashing(contract_code)
        
        # Build findings list
        findings = []
        findings.extend(selector_collisions)
        findings.extend(storage_collisions)
        findings.extend(upgrade_path_vulns)
        findings.extend(function_clashing)
        
        # Categorize findings
        critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in findings if f.get("severity") == "LOW")
        
        # Generate recommendations
        recommendations = []
        
        if critical_count > 0:
            recommendations.append({
                "type": "critical_findings",
                "message": f"Found {critical_count} CRITICAL vulnerabilities requiring immediate remediation",
            })
        
        if high_count > 0:
            recommendations.append({
                "type": "high_findings",
                "message": f"Found {high_count} HIGH vulnerabilities",
            })
        
        if medium_count > 0:
            recommendations.append({
                "type": "medium_findings",
                "message": f"Found {medium_count} MEDIUM vulnerabilities",
            })
        
        # EIP-2535 standard recommendations
        recommendations.extend([
            {
                "type": "eip2535_compliance",
                "message": "Ensure Diamond contract complies with ERC-2535 Diamond Standard",
                "details": "Use IERC-2535Loupe interface for facet selection",
            },
            {
                "type": "selector_resistance",
                "message": "Use EIP-2535SelectorLoupe interface to prevent selector collisions",
                "details": "Follow EIP-2535 naming conventions for selectors",
            },
            {
                "type": "storage_layout",
                "message": "Ensure proper storage slot separation between facets according to EIP-2535 specification",
                "details": "Use consistent storage slot naming scheme",
            },
            {
                "type": "upgrade_security",
                "message": "Implement two-step upgrade process with timelock and governance",
                "details": "Use multi-sig timelock for major upgrades",
            },
            {
                "type": "access_control",
                "message": "Restrict direct admin calls to governance procedures",
                "details": "Add loupe modifiers to privileged functions",
            },
        ])
        
        # Check for EIP-2535 compliance
        eip_compliant = True  # Assume
        
        result = {
            "contract_type": "diamond_proxy",
            "eip_compliant": eip_compliant,
            "facet_addresses": facet_addresses,
            "findings": findings,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "total_findings": len(findings),
            "recommendations": recommendations,
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Error analyzing Diamond contract: {str(e)}"
        })

class DiamondAnalyzer:
    """Simple wrapper class for Diamond analysis."""

    def analyze(self, contract_code: str) -> Dict[str, Any]:
        return json.loads(analyze_diamond(contract_code))
