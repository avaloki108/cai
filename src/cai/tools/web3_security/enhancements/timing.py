"""
Timing & Ordering Analysis

Analyzes transaction ordering assumptions and timing-based vulnerabilities.

Based on exploit_db.jsonl patterns for:
- Block timestamp manipulation windows
- Multi-block attack opportunities
- Functions that assume atomic execution but don't
- State changes visible in mempool before confirmation
"""

import json
import re
from typing import Any, Dict, List
from cai.sdk.agents import function_tool


# Timing-based vulnerability patterns
TIMING_PATTERNS = {
    "timestamp_manipulation": {
        "code_signatures": ["block.timestamp", "now", "time"],
        "exploit_description": "Using block.timestamp for time-sensitive operations allows manipulation",
        "negative_patterns": ["require(block.timestamp > deadline)", "use block.number instead", "use verifiable random values"],
        "test_assertion": "Verify block.timestamp is not used for critical timing logic",
    },
    "atomic_execution_assumption": {
        "code_signatures": ["transfer(", "transferFrom(", "approve(", "mint(", "burn("],
        "exploit_description": "Function assumes transaction executes atomically but doesn't",
        "negative_patterns": ["checks-effects-interactions pattern", "nonReentrant modifier", "lock state changes before external calls"],
        "test_assertion": "Verify state changes occur before external calls or mutex lock is used",
    },
    "mempool_visibility": {
        "code_signatures": ["balanceOf(", "allowance", "totalSupply"],
        "exploit_description": "Balance checks visible in mempool before transaction - race condition",
        "negative_patterns": ["check balances before updates", "use require on changed state", "use locks"],
        "test_assertion": "Verify balances are checked atomically with state updates",
    },
    "multi_block_attack": {
        "code_signatures": ["block.number", "blockhash", "tx.origin"],
        "exploit_description": "Multiple transactions in same block or across blocks - execution order issues",
        "negative_patterns": ["use block.number for sequencing", "avoid tx.origin for access control"],
        "test_assertion": "Verify block ordering assumptions are explicit",
    },
}


def _extract_function_calls_with_timing(
    code: str,
    timing_sensitive_vars: List[str]
) -> List[Dict[str, Any]]:
    """
    Extract function calls and analyze timing assumptions.
    
    Returns function calls with timing sensitivity analysis.
    """
    calls_with_timing = []
    
    # Pattern for external calls before state updates
    external_before_state_pattern = r'\.call\s*\([^)]*\)[^;\s*(?:[^)]*\);'
    
    # Pattern for state-changing operations
    state_change_pattern = r'(balances?\[[^\]]*\s*=\s*[^)]*\);'
    
    for func_match in re.finditer(r'function\s+(\w+)\s*\([^)]*\)', code, re.MULTILINE):
        func_name = func_match.group(1)
        full_call = func_match.group()
        
        # Check if function has timing issues
        func_lower = func_name.lower()
        timing_issues = []
        
        # Check for external calls before state updates
        external_calls = []
        for ext_match in re.finditer(external_before_state_pattern, full_call):
            if ext_match.group(2):  # The external call
                external_call = ext_match.group(2)
                external_calls.append(external_call)
        
        # Check for state changes after external calls
        state_changes = []
        for state_change_match in re.finditer(state_change_pattern, full_call):
            if state_change_match.group(2):  # The state change
                state_changes.append(state_change_match.group(2))
        
        if external_calls and not state_changes:
            timing_issues.append({
                "function": func_name,
                "issue": "state_changes_after_external_calls",
                "severity": "MEDIUM",
                "description": f"Function '{func_name}' has external calls but no state changes - may leave state vulnerable to reentrancy",
                "external_calls": external_calls,
                "recommendation": "Add state updates before external calls or use mutex",
            })
        elif state_changes and external_calls:
            timing_issues.append({
                "function": func_name,
                "issue": "no_state_changes",
                "severity": "MEDIUM",
                "description": f"Function '{func_name}' has state changes but no external calls - timing assumption may be incorrect",
                "state_changes": state_changes,
                "recommendation": "Verify if state changes are properly ordered",
            })
        
        if timing_issues:
            calls_with_timing[func_name] = {
                "function": func_name,
                "external_calls": external_calls,
                "state_changes": state_changes,
                "timing_issues": timing_issues,
            }
            calls_with_timing.append(calls_with_timing[func_name])
    
    return calls_with_timing


@function_tool
def analyze_timestamp_manipulation(
    contract_code: str,
    block_number: int = 0,
    ctf=None
) -> str:
    """
    Analyze for block timestamp manipulation vulnerabilities.
    
    Args:
        contract_code: Solidity source code
        block_number: Block number for analysis (default: 0)
    
    Returns:
        JSON with timestamp manipulation analysis
    """
    try:
        findings = []
        code_lower = contract_code.lower()
        
        # Check for timestamp usage
        if "block.timestamp" in code_lower or "now" in code_lower or "time" in code_lower:
            timestamp_pattern = TIMING_PATTERNS["timestamp_manipulation"]
            
            # Check for problematic patterns
            for pattern in timestamp_pattern["code_signatures"]:
                if pattern in code_lower:
                    findings.append({
                        "type": "timestamp_manipulation",
                        "severity": timestamp_pattern["severity"],
                        "description": timestamp_pattern["exploit_description"],
                        "pattern_matched": pattern,
                        "recommendation": timestamp_pattern["negative_patterns"][0],
                    })
            
            # Check for negative patterns
            for neg_pattern in timestamp_pattern["negative_patterns"]:
                if neg_pattern in code_lower:
                    findings.append({
                        "type": "timestamp_manipulation",
                        "severity": "MEDIUM",
                        "description": f"Found negative pattern: {neg_pattern}",
                        "recommendation": timestamp_pattern["negative_patterns"][1],
                    })
        
        if not findings:
            return json.dumps({
                "timestamp_manipulation_detected": False,
                "message": "No timestamp manipulation vulnerabilities found",
            })
        
        return json.dumps({
            "timestamp_manipulation_detected": len(findings) > 0,
            "findings": findings,
        "vulnerabilities_count": len(findings),
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Error analyzing timestamp manipulation: {str(e)}"
        })


@function_tool
def analyze_atomic_execution_assumptions(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze for atomic execution assumptions.
    
    Checks for functions that assume atomic execution
    but don't validate state changes or external calls.
    
    Args:
        contract_code: Solidity source code
    
    Returns:
        JSON with atomic execution vulnerabilities
    """
    try:
        findings = []
        code_lower = contract_code.lower()
        pattern = TIMING_PATTERNS["atomic_execution_assumption"]
        
        # Find functions with timing-sensitive operations
        timing_sensitive_vars = []
        if "transfer(" in code_lower or "transferfrom(" in code_lower or "approve(" in code_lower or "mint(" in code_lower or "burn(" in code_lower:
            timing_sensitive_vars.extend(["balances", "allowance", "totalsupply"])
        
        if "swap(" in code_lower or "exchange(" in code_lower:
            timing_sensitive_vars.extend(["balances"])
        
        # Analyze each function
        for func_name in ["transfer", "approve", "mint", "burn"]:
            if func_name not in code_lower:
                continue
            
            # Find function definition
            func_pattern = rf'function\s+{func_name}\s*\([^)]*\)\s*{{'
            func_match = re.search(func_pattern, code, re.MULTILINE)
            
            if not func_match:
                continue
            
            # Extract function body
            func_start = func_match.start() + len("function ".lower())
            func_end = code.find("}", func_start)
            if func_end == -1:
                func_body = code[func_start:func_end+1]
            else:
                # Find closing brace
                close_pos = func_body.rfind("}", func_start)
                if close_pos == -1:
                    func_body = code[func_start:close_pos+1:func_end+1]
            
            # Check for timing issues
            func_issues = []
            
            # Check for external calls without state updates
            external_calls = []
            for ext_match in re.finditer(external_before_state_pattern, func_body):
                external_call = ext_match.group(2)
                external_calls.append(external_call)
            
            # Check for state changes after external calls
            state_changes = []
            for state_change_match in re.finditer(state_change_pattern, func_body):
                if state_change_match.group(2):
                    state_changes.append(state_change_match.group(2))
            
            if external_calls and not state_changes:
                func_issues.append({
                    "function": func_name,
                    "issue": "assumes_atomic_execution",
                    "severity": "HIGH",
                    "description": "Function '{func_name}' assumes atomic execution but doesn't validate state before external calls",
                    "external_calls": external_calls,
                    "state_changes": state_changes,
                    "recommendation": "Add state validation before external calls or use ReentrancyGuard",
                })
            
            elif not external_calls:
                func_issues.append({
                    "function": func_name,
                    "issue": "assumes_atomic_execution",
                    "severity": "HIGH",
                    "description": f"Function '{func_name}' assumes atomic execution but has no external calls - timing assumption may be incorrect",
                    "recommendation": "Verify if atomic execution is actually required",
                })
        
        # Return findings
        if func_issues:
            findings.extend(func_issues)
        
        return json.dumps({
            "timing_sensitive_vars": timing_sensitive_vars,
            "findings": findings,
            "total_findings": len(findings),
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error analyzing atomic execution assumptions: {str(e)}"})


@function_tool
def analyze_mempool_visibility(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze mempool visibility vulnerabilities.
    
    Checks for:
    - Balance checks before transfers
    - State changes visible in mempool
    - Race conditions
    
    Args:
        contract_code: Solidity source code
    
    Returns:
        JSON with mempool visibility analysis
    """
    try:
        findings = []
        code_lower = contract_code.lower()
        pattern = TIMING_PATTERNS["mempool_visibility"]
        
        # Check for balance-related functions
        balance_functions = ["balanceOf", "allowance", "transfer", "approve", "totalsupply"]
        
        for func_name in balance_functions:
            if func_name not in code_lower:
                continue
        
            # Find function definition
            func_pattern = rf'function\s+{func_name}\s*\([^)]*\)\s*{{'
            func_match = re.search(func_pattern, code, re.MULTILINE)
            
            if not func_match:
                continue
            
            # Extract function body
            func_start = func_match.start() + len("function ".lower())
            func_end = code.find("}", func_start)
            if func_end == -1:
                func_body = code[func_start:func_end+1]
            else:
                # Find closing brace
                close_pos = func_body.rfind("}", func_start)
                if close_pos == -1:
                    func_body = code[func_start:close_pos+1:func_end+1]
            
            # Analyze for issues
            func_issues = []
            
            # Check if balanceOf is called
            if "balanceof" in code_lower and "allowance" in code_lower:
                func_issues.append({
                    "function": func_name,
                    "issue": "balance_check_without_allowance",
                    "severity": "MEDIUM",
                    "description": "allowance used to check balanceOf but doesn't enforce caller restriction - potential unauthorized balance read",
                })
            
            # Check for transfer/receive
            if "transfer(" in code_lower or "received" in code_lower:
                # Check if balance updates before
                update_pattern = r'(balances?\[[^\]]*\s*=\s*[^)]*\);'
                update_matches = re.finditer(update_pattern, code, re.MULTILINE)
                
                if update_matches:
                    func_issues.append({
                        "function": func_name,
                        "issue": "balance_update_race_condition",
                        "severity": "HIGH",
                        "description": "Balance updated without proper check - race condition",
                        "recommendation": "Add mutex lock or checks-effects-interactions pattern",
                    })
            
            # Check for approve
            if "approve(" in code_lower:
                # Check if allowance updates before
                update_pattern = r'(allowance?\[[^\]]*\s*=\s*[^)]*\);'
                update_matches = re.finditer(update_pattern, code, re.MULTILINE)
                
                if update_matches:
                    func_issues.append({
                        "function": func_name,
                        "issue": "allowance_update_race_condition",
                        "severity": "HIGH",
                        "description": "Allowance updated without proper check - race condition",
                        "recommendation": "Add mutex lock or checks-effects-interactions pattern",
                    })
        
        if func_issues:
            findings.extend(func_issues)
        
        return json.dumps({
            "balance_functions": balance_functions,
            "findings": findings,
            "total_findings": len(findings),
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error analyzing mempool visibility: {str(e)}"})


@function_tool
def analyze_multi_block_attacks(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze multi-block attack opportunities.
    
    Checks for:
    - Multiple transactions in same block or across blocks
    - Execution order issues
    
    Args:
        contract_code: Solidity source code
    
    Returns:
        JSON with multi-block attack analysis
    """
    try:
        findings = []
        code_lower = contract_code.lower()
        pattern = TIMING_PATTERNS["multi_block_attack"]
        
        # Find block.number/block.hash/block.timestamp usage
        block_usage = []
        if "block.number" in code_lower or "blockhash" in code_lower or "block.timestamp" in code_lower:
            block_usage.append("block.number")
        
        # Find tx.origin usage
        if "tx.origin" in code_lower or "msg.sender" in code_lower:
            block_usage.append("tx.origin")
        
        # Check for multi-block pattern
        if "for(" in code_lower or "while(" in code_lower:
            findings.append({
                "type": "multi_block_race_condition",
                "severity": "HIGH",
                "description": "Function uses for/while loop - execution order issues across blocks",
                "recommendation": "Use tx.origin for access control or reentrancy protection",
            })
        
        # Check for sequential assumptions
        if "block.timestamp" in code_lower or "now" in code_lower:
            findings.append({
                "type": "sequential_assumption",
                "severity": "MEDIUM",
                "description": "Uses block.timestamp or now for time-sensitive operations - may have race conditions",
                "recommendation": "Use verifiable randomness or timestamp commitments",
            })
        
        # Check for state changes without validation
        state_change_pattern = r'(balances?\[[^\]]*\s*=\s*[^)]*\);'
        state_change_matches = re.finditer(state_change_pattern, code, re.MULTILINE)
        
        for match in state_change_matches:
            findings.append({
                "type": "state_change_race_condition",
                "severity": "HIGH",
                "description": f"State changes found without explicit ordering validation",
                "recommendation": "Add event-based state transitions or mutex locks",
            })
        
        return json.dumps({
            "block_usage": block_usage,
            "findings": findings,
            "vulnerabilities_count": len(findings),
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error analyzing multi-block attacks: {str(e)}"})

@function_tool
def analyze_transaction_ordering(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze transaction ordering assumptions across the contract.
    
    Checks:
    - Functions that assume atomic execution order
    - State dependencies that require specific order
    - Callback functions that could execute out of order
    
    Args:
        contract_code: Solidity source code
    
    Returns:
        JSON with transaction ordering analysis
    """
    try:
        findings = []
        code_lower = contract_code.lower()
        
        # Track function order assumptions
        order_assumptions = {}
        
        # Extract function definitions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)'
        for match in re.finditer(func_pattern, contract_code, re.MULTILINE):
            func_name = match.group(1)
            position = match.start()
            order_assumptions[func_name] = {
                "assumes_atomic": True,
                "position": position,
            }
        
        # Check for callback reentrancy vulnerabilities
        callback_names = ["onERC721Received", "onERC1155Received", "fallback", "receive"]
        for cb_name in callback_names:
            if cb_name.lower() in code_lower:
                # Check for reentrancy protection
                has_protection = (
                    "nonreentrant" in code_lower or
                    "reentrancyguard" in code_lower or
                    "_status" in code_lower
                )
                
                if not has_protection:
                    findings.append({
                        "type": "reentrancy_vulnerability",
                        "severity": "HIGH",
                        "description": f"Callback '{cb_name}' may lack reentrancy protection",
                        "function": cb_name,
                        "recommendation": "Add ReentrancyGuard modifier or check-effects-interactions",
                    })
        
        # Check for state changes after external calls
        external_call_pattern = r'\.(call|delegatecall|staticcall)\s*\('
        state_change_pattern = r'(\w+)\s*=\s*'
        
        # Find external calls
        external_calls = list(re.finditer(external_call_pattern, contract_code))
        state_changes = list(re.finditer(state_change_pattern, contract_code))
        
        for ext_call in external_calls:
            call_pos = ext_call.start()
            # Check for state changes after this call
            for state_change in state_changes:
                if state_change.start() > call_pos:
                    # State change after external call - potential ordering issue
                    var_name = state_change.group(1)
                    if var_name not in ['result', 'success', 'data', 'returndata']:
                        findings.append({
                            "type": "state_after_external_call",
                            "severity": "MEDIUM",
                            "description": f"State variable '{var_name}' modified after external call",
                            "recommendation": "Move state changes before external calls (CEI pattern)",
                        })
                    break  # Only report first occurrence per external call
        
        return json.dumps({
            "ordering_assumptions": order_assumptions,
            "findings": findings,
            "total_findings": len(findings),
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Error analyzing transaction ordering: {str(e)}"
        })