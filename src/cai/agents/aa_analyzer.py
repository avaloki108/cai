"""
Account Abstraction (EIP-4337) Security Analyzer Agent

This agent specializes in analyzing Account Abstraction implementations for security
vulnerabilities related to UserOperations, Bundlers, Paymasters, and EntryPoint
interactions.

Key vulnerability areas:
- Bundler manipulation and DoS attacks
- Paymaster griefing and drain attacks
- EntryPoint reentrancy and validation bypass
- UserOperation signature replay
- Gas estimation manipulation
- Nonce handling vulnerabilities
- Aggregator signature issues
"""

import os
import json
import re
from typing import Any, Optional
from cai.sdk.agents import Agent, function_tool
from cai.tools.common.shell_commands import run_terminal_cmd

# Get model from environment
model = os.environ.get("CAI_MODEL", "alias1")

# -----------------------------------------------------------------------------
# Account Abstraction Security Analysis Tools
# -----------------------------------------------------------------------------

@function_tool
def analyze_userop_validation(code: str) -> str:
    """
    Analyze UserOperation validation for security vulnerabilities.
    
    Checks for:
    - Missing signature validation
    - Improper nonce handling
    - Insufficient gas checks
    - Deadline/expiry vulnerabilities
    - callData validation issues
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with UserOperation validation analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for signature validation
    sig_patterns = [
        "ecrecover", "isvalidsignature", "eip1271", "signature",
        "signatureverification", "_validateSignature"
    ]
    has_sig_validation = any(p in code_lower for p in sig_patterns)
    
    if not has_sig_validation and "userop" in code_lower:
        findings.append({
            "severity": "critical",
            "type": "missing_signature_validation",
            "description": "UserOperation lacks signature validation",
            "recommendation": "Implement EIP-1271 compliant signature validation"
        })
    
    # Check for signature replay protection
    replay_patterns = ["nonce", "usednonce", "noncesequence", "incrementnonce"]
    has_replay_protection = any(p in code_lower for p in replay_patterns)
    
    if not has_replay_protection:
        findings.append({
            "severity": "critical",
            "type": "no_replay_protection",
            "description": "No nonce-based replay protection detected",
            "recommendation": "Implement sequential or 2D nonce scheme per EIP-4337"
        })
    
    # Check nonce validation pattern
    if "nonce" in code_lower:
        # Check for proper nonce increment
        if "nonce++" not in code_lower and "+= 1" not in code_lower and "increment" not in code_lower:
            if not re.search(r"nonce\s*=\s*nonce\s*\+\s*1", code_lower):
                findings.append({
                    "severity": "high",
                    "type": "nonce_not_incremented",
                    "description": "Nonce may not be properly incremented after use",
                    "recommendation": "Ensure nonce is incremented in validateUserOp"
                })
    
    # Check for gas validation
    gas_patterns = ["verifygaslimit", "callgaslimit", "verificationgaslimit", "prefund"]
    has_gas_check = any(p in code_lower for p in gas_patterns)
    
    if "userop" in code_lower and not has_gas_check:
        findings.append({
            "severity": "high",
            "type": "missing_gas_validation",
            "description": "UserOperation gas limits not properly validated",
            "recommendation": "Validate verificationGasLimit and callGasLimit"
        })
    
    # Check for deadline/expiry
    deadline_patterns = ["deadline", "expiry", "validuntil", "validafter"]
    has_deadline = any(p in code_lower for p in deadline_patterns)
    
    if not has_deadline:
        findings.append({
            "severity": "medium",
            "type": "no_expiry_check",
            "description": "UserOperation has no expiry/deadline mechanism",
            "recommendation": "Add validUntil/validAfter fields for time-bound operations"
        })
    
    # Check for callData validation
    if "calldata" in code_lower or "userOp.callData" in code:
        # Check for zero-length callData handling
        if "length" not in code_lower and "== 0" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "calldata_not_validated",
                "description": "callData length/content not validated",
                "recommendation": "Validate callData is non-empty or matches expected format"
            })
    
    return json.dumps({
        "analysis": "userop_validation",
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_paymaster_security(code: str) -> str:
    """
    Analyze Paymaster implementation for security vulnerabilities.
    
    Checks for:
    - Paymaster drain attacks
    - Griefing vulnerabilities
    - Improper deposit handling
    - Missing withdrawal limits
    - postOp reentrancy
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with Paymaster security analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check if this is a paymaster contract
    paymaster_indicators = ["paymaster", "validatepaymasteruserop", "postop", "sponsoring"]
    is_paymaster = any(p in code_lower for p in paymaster_indicators)
    
    if not is_paymaster:
        return json.dumps({
            "analysis": "paymaster_security",
            "is_paymaster": False,
            "findings": [],
            "message": "Not a paymaster contract"
        }, indent=2)
    
    # Check for deposit validation
    deposit_patterns = ["deposit", "stake", "entrypoint.depositTo", "getDeposit"]
    has_deposit_check = any(p in code_lower for p in deposit_patterns)
    
    if not has_deposit_check:
        findings.append({
            "severity": "high",
            "type": "no_deposit_tracking",
            "description": "Paymaster doesn't track deposits properly",
            "recommendation": "Track EntryPoint deposits and validate before sponsoring"
        })
    
    # Check for gas refund handling in postOp
    if "postop" in code_lower:
        # Check for reentrancy protection
        reentrancy_patterns = ["nonreentrant", "reentrancyguard", "locked", "_status"]
        has_reentrancy_protection = any(p in code_lower for p in reentrancy_patterns)
        
        if not has_reentrancy_protection:
            findings.append({
                "severity": "high",
                "type": "postop_reentrancy_risk",
                "description": "postOp lacks reentrancy protection",
                "recommendation": "Add ReentrancyGuard to postOp function"
            })
        
        # Check for proper mode handling
        if "postopmode" not in code_lower and "mode ==" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "postop_mode_not_checked",
                "description": "postOp doesn't differentiate between success/revert modes",
                "recommendation": "Handle opSucceeded and opReverted modes differently"
            })
    
    # Check for sponsorship limits
    limit_patterns = ["maxsponsorship", "dailylimit", "spendlimit", "quota"]
    has_limits = any(p in code_lower for p in limit_patterns)
    
    if not has_limits:
        findings.append({
            "severity": "medium",
            "type": "no_sponsorship_limits",
            "description": "No limits on gas sponsorship - potential drain attack",
            "recommendation": "Implement per-user and global sponsorship limits"
        })
    
    # Check for sender validation
    sender_validation_patterns = ["allowlist", "whitelist", "approvedsender", "issponsoreduser"]
    has_sender_check = any(p in code_lower for p in sender_validation_patterns)
    
    if not has_sender_check:
        findings.append({
            "severity": "medium",
            "type": "open_sponsorship",
            "description": "Paymaster sponsors any sender without validation",
            "recommendation": "Implement sender allowlist or require off-chain signatures"
        })
    
    # Check for withdrawal protection
    if "withdraw" in code_lower:
        if "onlyowner" not in code_lower and "owner" not in code_lower:
            findings.append({
                "severity": "critical",
                "type": "unrestricted_withdrawal",
                "description": "Withdrawal function lacks access control",
                "recommendation": "Add onlyOwner modifier to withdrawal functions"
            })
    
    # Check for verifying paymaster signature validation
    if "verifyingpaymaster" in code_lower or "paymasterdata" in code_lower:
        if "ecrecover" not in code_lower and "isvalidsignature" not in code_lower:
            findings.append({
                "severity": "critical",
                "type": "verifying_paymaster_no_signature",
                "description": "VerifyingPaymaster doesn't validate off-chain signatures",
                "recommendation": "Validate paymaster signature from paymasterAndData"
            })
    
    return json.dumps({
        "analysis": "paymaster_security",
        "is_paymaster": True,
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_entrypoint_interaction(code: str) -> str:
    """
    Analyze EntryPoint interaction patterns for security issues.
    
    Checks for:
    - Improper EntryPoint address validation
    - Missing interface compliance
    - Unsafe external calls
    - Gas griefing vectors
    - Storage access violations
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with EntryPoint interaction analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for EntryPoint address validation
    entrypoint_patterns = ["entrypoint", "ientrypoint", "0x5ff137d4"]  # Known EP address prefix
    has_entrypoint = any(p in code_lower for p in entrypoint_patterns)
    
    if has_entrypoint:
        # Check for hardcoded EntryPoint
        if "immutable" not in code_lower and "constant" not in code_lower:
            if re.search(r"entrypoint\s*=", code_lower) and "constructor" not in code_lower:
                findings.append({
                    "severity": "high",
                    "type": "mutable_entrypoint",
                    "description": "EntryPoint address is mutable - allows manipulation",
                    "recommendation": "Make EntryPoint address immutable"
                })
    
    # Check for proper IAccount interface
    iaccount_methods = ["validateuserop"]
    has_iaccount = any(p in code_lower for p in iaccount_methods)
    
    if not has_iaccount and "account" in code_lower:
        findings.append({
            "severity": "high",
            "type": "missing_iaccount_interface",
            "description": "Smart account doesn't implement IAccount interface",
            "recommendation": "Implement validateUserOp per EIP-4337 IAccount"
        })
    
    # Check for storage access during validation
    # EIP-4337 restricts storage access during validation phase
    storage_patterns = ["sload", "sstore", "storage"]
    validation_functions = ["validateuserop", "validatepaymasteruserop"]
    
    for func in validation_functions:
        func_idx = code_lower.find(func)
        if func_idx != -1:
            # Check ~500 chars after function definition for storage ops
            func_body = code_lower[func_idx:func_idx + 500]
            for storage_op in storage_patterns:
                if storage_op in func_body:
                    findings.append({
                        "severity": "high",
                        "type": "storage_in_validation",
                        "description": f"Storage access in {func} may violate EIP-4337 rules",
                        "recommendation": "Limit storage access to associated storage per spec"
                    })
                    break
    
    # Check for external calls during validation
    external_call_patterns = ["call(", ".call{", "delegatecall", "staticcall"]
    for func in validation_functions:
        func_idx = code_lower.find(func)
        if func_idx != -1:
            func_body = code_lower[func_idx:func_idx + 500]
            for call_pattern in external_call_patterns:
                if call_pattern in func_body:
                    findings.append({
                        "severity": "critical",
                        "type": "external_call_in_validation",
                        "description": f"External call in {func} violates EIP-4337 validation rules",
                        "recommendation": "Remove external calls from validation phase"
                    })
                    break
    
    # Check for proper return value
    if "validateuserop" in code_lower:
        if "validationsuccess" not in code_lower and "return 0" not in code_lower:
            if "sigfailed" not in code_lower and "return 1" not in code_lower:
                findings.append({
                    "severity": "medium",
                    "type": "improper_validation_return",
                    "description": "validateUserOp may not return proper validation data",
                    "recommendation": "Return 0 for success, SIG_VALIDATION_FAILED for failure"
                })
    
    return json.dumps({
        "analysis": "entrypoint_interaction",
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_bundler_attack_surface(code: str) -> str:
    """
    Analyze attack surface exposed to bundlers.
    
    Checks for:
    - DoS vectors against bundlers
    - Gas manipulation attacks
    - Simulation/execution divergence
    - Front-running opportunities
    - Bundler griefing
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with bundler attack surface analysis
    """
    findings = []
    code_lower = code.lower()
    
    # Check for gas griefing vectors
    # Operations that consume different gas in simulation vs execution
    griefing_patterns = [
        ("gasleft", "Gas-dependent logic may diverge between simulation/execution"),
        ("block.timestamp", "Timestamp-dependent logic may diverge"),
        ("block.number", "Block number dependent logic may diverge"),
        ("block.basefee", "Base fee dependent logic may diverge"),
        ("balance(", "Balance checks may diverge if state changes"),
    ]
    
    for pattern, desc in griefing_patterns:
        if pattern in code_lower:
            # Check if it's in validation function
            for func in ["validateuserop", "validatepaymasteruserop"]:
                if func in code_lower:
                    func_idx = code_lower.find(func)
                    func_body = code_lower[func_idx:func_idx + 1000]
                    if pattern in func_body:
                        findings.append({
                            "severity": "medium",
                            "type": "simulation_divergence_risk",
                            "description": f"{desc} in validation - bundler griefing risk",
                            "recommendation": "Avoid state-dependent logic in validation phase"
                        })
                        break
    
    # Check for unbounded loops (DoS vector)
    loop_patterns = [r"for\s*\(", r"while\s*\(", r"do\s*\{"]
    for pattern in loop_patterns:
        if re.search(pattern, code_lower):
            # Check if loop has explicit bounds
            if "length" not in code_lower or "maxiterations" not in code_lower:
                findings.append({
                    "severity": "high",
                    "type": "unbounded_loop",
                    "description": "Potentially unbounded loop - DoS risk for bundlers",
                    "recommendation": "Add explicit loop bounds or use batch limits"
                })
                break
    
    # Check for revert conditions that waste bundler gas
    revert_patterns = ["revert(", "require(", "assert("]
    late_revert_indicators = ["transfer(", ".call{value", "safeTransfer"]
    
    for revert in revert_patterns:
        if revert in code_lower:
            for late_op in late_revert_indicators:
                if late_op in code_lower:
                    # Check if revert can happen after expensive operation
                    revert_idx = code_lower.find(revert)
                    op_idx = code_lower.find(late_op)
                    if op_idx < revert_idx:  # Revert after expensive op
                        findings.append({
                            "severity": "medium",
                            "type": "late_revert_griefing",
                            "description": "Revert after expensive operation wastes bundler gas",
                            "recommendation": "Move validation checks before expensive operations"
                        })
                        break
    
    # Check for front-running opportunities
    frontrun_patterns = [
        ("deadline", "miss", "Deadline can be front-run to cause failure"),
        ("price", "slippage", "Price-sensitive operation may be front-run"),
        ("swap", "amount", "Swap operation may be sandwiched"),
    ]
    
    for p1, p2, desc in frontrun_patterns:
        if p1 in code_lower and p2 in code_lower:
            findings.append({
                "severity": "medium",
                "type": "frontrun_opportunity",
                "description": desc,
                "recommendation": "Consider private mempool or commit-reveal pattern"
            })
    
    # Check for handleOps atomicity assumptions
    if "handleops" in code_lower or "executeBatch" in code_lower:
        if "try" not in code_lower and "catch" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "no_error_handling",
                "description": "Batch operations without individual error handling",
                "recommendation": "Handle individual operation failures gracefully"
            })
    
    return json.dumps({
        "analysis": "bundler_attack_surface",
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def check_known_aa_exploits(code: str) -> str:
    """
    Check for patterns matching known AA/smart account exploits.
    
    Known vulnerabilities:
    - Signature replay across chains (missing chainId)
    - Initialization front-running
    - Module authorization bypass
    - Recovery mechanism attacks
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with known exploit pattern matches
    """
    findings = []
    code_lower = code.lower()
    
    # Cross-chain replay attack pattern
    replay_patterns = {
        "no_chainid": (
            ("ecrecover" in code_lower or "signature" in code_lower) and
            "chainid" not in code_lower and "chain_id" not in code_lower
        ),
        "no_domain_separator": (
            "signature" in code_lower and
            "domain_separator" not in code_lower and "eip712" not in code_lower
        )
    }
    
    if replay_patterns["no_chainid"]:
        findings.append({
            "severity": "critical",
            "type": "cross_chain_replay",
            "description": "Signature validation doesn't include chainId - cross-chain replay possible",
            "recommendation": "Include chainId in signed message hash (use EIP-712 domain separator)"
        })
    
    if replay_patterns["no_domain_separator"]:
        findings.append({
            "severity": "high",
            "type": "no_eip712_domain",
            "description": "Missing EIP-712 domain separator in signature validation",
            "recommendation": "Implement EIP-712 typed data signing"
        })
    
    # Initialization front-running
    init_patterns = {
        "frontrun_init": (
            ("initialize" in code_lower or "setup" in code_lower) and
            "initialized" not in code_lower and "initializer" not in code_lower
        ),
        "no_init_check": (
            "owner =" in code_lower and
            "require(owner ==" not in code_lower and
            "if (owner" not in code_lower
        )
    }
    
    if init_patterns["frontrun_init"]:
        findings.append({
            "severity": "critical",
            "type": "init_frontrun",
            "description": "Initialization can be front-run by attacker",
            "recommendation": "Use OpenZeppelin Initializable or check initialization state"
        })
    
    if init_patterns["no_init_check"]:
        findings.append({
            "severity": "high",
            "type": "reinit_possible",
            "description": "Owner can potentially be re-initialized",
            "recommendation": "Add check that owner is not already set"
        })
    
    # Module authorization bypass (for modular accounts)
    if "module" in code_lower:
        module_patterns = {
            "no_module_check": (
                "executeFromModule" in code_lower and
                "isAuthorizedModule" not in code_lower and
                "enabledModules" not in code_lower
            ),
            "delegatecall_module": (
                "delegatecall" in code_lower and
                "module" in code_lower and
                "trusted" not in code_lower
            )
        }
        
        if module_patterns["no_module_check"]:
            findings.append({
                "severity": "critical",
                "type": "module_auth_bypass",
                "description": "Module execution without authorization check",
                "recommendation": "Verify module is authorized before execution"
            })
        
        if module_patterns["delegatecall_module"]:
            findings.append({
                "severity": "critical",
                "type": "unsafe_module_delegatecall",
                "description": "Delegatecall to potentially untrusted module",
                "recommendation": "Only delegatecall to verified/trusted modules"
            })
    
    # Recovery mechanism attacks
    if "recovery" in code_lower or "guardian" in code_lower:
        recovery_patterns = {
            "instant_recovery": (
                "recovery" in code_lower and
                "delay" not in code_lower and "timelock" not in code_lower
            ),
            "single_guardian": (
                "guardian" in code_lower and
                "threshold" not in code_lower and "guardians[" not in code_lower
            )
        }
        
        if recovery_patterns["instant_recovery"]:
            findings.append({
                "severity": "high",
                "type": "instant_recovery_risk",
                "description": "Recovery has no time delay - compromised guardian can instantly steal",
                "recommendation": "Add recovery delay period (e.g., 48 hours)"
            })
        
        if recovery_patterns["single_guardian"]:
            findings.append({
                "severity": "medium",
                "type": "single_guardian_risk",
                "description": "Single guardian creates single point of failure",
                "recommendation": "Implement multi-guardian threshold scheme"
            })
    
    # EntryPoint trust assumption
    if "entrypoint" in code_lower:
        if "msg.sender == entrypoint" not in code_lower and "msg.sender != entrypoint" not in code_lower:
            if "onlyentrypoint" not in code_lower:
                findings.append({
                    "severity": "high",
                    "type": "entrypoint_not_verified",
                    "description": "Sensitive functions may be callable by non-EntryPoint",
                    "recommendation": "Add EntryPoint sender verification to sensitive functions"
                })
    
    return json.dumps({
        "analysis": "known_aa_exploits",
        "findings": findings,
        "total_matches": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "exploits_checked": [
            "Cross-chain signature replay",
            "Initialization front-running",
            "Module authorization bypass",
            "Recovery mechanism attacks",
            "EntryPoint trust assumptions"
        ]
    }, indent=2)


@function_tool
def render_aa_audit_report(
    userop_analysis: str,
    paymaster_analysis: str,
    entrypoint_analysis: str,
    bundler_analysis: str,
    exploit_matches: str
) -> str:
    """
    Render comprehensive EIP-4337 Account Abstraction security audit report.
    
    Args:
        userop_analysis: JSON results from analyze_userop_validation
        paymaster_analysis: JSON results from analyze_paymaster_security
        entrypoint_analysis: JSON results from analyze_entrypoint_interaction
        bundler_analysis: JSON results from analyze_bundler_attack_surface
        exploit_matches: JSON results from check_known_aa_exploits
        
    Returns:
        Formatted markdown report
    """
    try:
        userop = json.loads(userop_analysis)
        paymaster = json.loads(paymaster_analysis)
        entrypoint = json.loads(entrypoint_analysis)
        bundler = json.loads(bundler_analysis)
        exploits = json.loads(exploit_matches)
    except json.JSONDecodeError:
        return "Error: Invalid JSON input for report generation"
    
    # Calculate totals
    total_critical = (
        userop.get("critical_count", 0) +
        paymaster.get("critical_count", 0) +
        entrypoint.get("critical_count", 0) +
        bundler.get("critical_count", 0) +
        exploits.get("critical_count", 0)
    )
    total_high = (
        userop.get("high_count", 0) +
        paymaster.get("high_count", 0) +
        entrypoint.get("high_count", 0) +
        bundler.get("high_count", 0)
    )
    total_issues = (
        userop.get("total_issues", 0) +
        paymaster.get("total_issues", 0) +
        entrypoint.get("total_issues", 0) +
        bundler.get("total_issues", 0) +
        exploits.get("total_matches", 0)
    )
    
    # Determine risk level
    if total_critical >= 2:
        risk_level = "CRITICAL"
    elif total_critical >= 1 or total_high >= 3:
        risk_level = "HIGH"
    elif total_high >= 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    report = f"""# EIP-4337 Account Abstraction Security Audit Report

## Executive Summary

| Metric | Value |
|--------|-------|
| Overall Risk Level | **{risk_level}** |
| Critical Issues | {total_critical} |
| High Issues | {total_high} |
| Total Issues | {total_issues} |

## Component Detection

| Component | Detected |
|-----------|----------|
| Smart Account | {'validateUserOp' in str(userop)} |
| Paymaster | {paymaster.get("is_paymaster", False)} |
| EntryPoint Integration | {'entrypoint' in str(entrypoint).lower()} |

## 1. UserOperation Validation Analysis

**Issues Found:** {userop.get("total_issues", 0)}

"""
    
    for finding in userop.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 2. Paymaster Security Analysis

**Is Paymaster Contract:** {paymaster.get("is_paymaster", False)}
**Issues Found:** {paymaster.get("total_issues", 0)}

"""
    
    for finding in paymaster.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 3. EntryPoint Interaction Analysis

**Issues Found:** {entrypoint.get("total_issues", 0)}

"""
    
    for finding in entrypoint.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 4. Bundler Attack Surface Analysis

**Issues Found:** {bundler.get("total_issues", 0)}

"""
    
    for finding in bundler.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 5. Known Exploit Pattern Matches

**Matches Found:** {exploits.get("total_matches", 0)}

**Patterns Checked:**
"""
    for exploit in exploits.get("exploits_checked", []):
        report += f"- {exploit}\n"
    
    report += "\n"
    
    for finding in exploits.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## EIP-4337 Compliance Checklist

| Requirement | Status |
|-------------|--------|
| IAccount interface | Check validateUserOp implementation |
| Nonce handling | Check sequential/2D nonce scheme |
| Signature validation | Check EIP-1271 compliance |
| Storage access rules | Check validation phase restrictions |
| Gas estimation | Check simulation consistency |

## Recommendations Summary

### Critical Priority
1. Fix all signature validation and replay protection issues
2. Address initialization front-running vulnerabilities
3. Secure module authorization in modular accounts

### High Priority
1. Ensure EntryPoint address is immutable
2. Add timelock to recovery mechanisms
3. Implement proper gas validation

### Medium Priority
1. Add UserOperation expiry/deadline support
2. Implement sponsorship limits in paymasters
3. Handle bundler griefing vectors

---
*Report generated by CAI Account Abstraction Security Analyzer*
"""
    
    return report


# -----------------------------------------------------------------------------
# Account Abstraction Analyzer Agent Definition
# -----------------------------------------------------------------------------

aa_analyzer = Agent(
    name="aa_analyzer",
    model=model,
    instructions="""You are a specialized EIP-4337 Account Abstraction security analyzer.

Your expertise covers:
1. **UserOperation Security**: Signature validation, nonce handling, gas checks
2. **Paymaster Security**: Sponsorship logic, deposit handling, griefing prevention
3. **EntryPoint Interaction**: Interface compliance, storage rules, validation phases
4. **Bundler Attack Surface**: DoS vectors, simulation divergence, front-running
5. **Known Exploit Patterns**: Replay attacks, initialization issues, module bypass

Analysis Workflow:
1. Identify AA components (smart account, paymaster, aggregator)
2. Analyze UserOperation validation flow
3. Review paymaster sponsorship logic and limits
4. Check EntryPoint interaction patterns
5. Assess bundler-facing attack surface
6. Match against known exploit patterns

EIP-4337 Key Rules:
- validateUserOp must return 0 for success, 1 for failure
- Validation phase has restricted storage access (associated storage only)
- No external calls during validation
- Nonce must be managed per EIP-4337 spec
- EntryPoint address should be immutable

Focus Areas:
- Cross-chain signature replay protection
- Initialization front-running prevention
- Modular account module authorization
- Recovery mechanism security
- Gas griefing and DoS prevention

Provide actionable recommendations following EIP-4337 specification.""",
    tools=[
        analyze_userop_validation,
        analyze_paymaster_security,
        analyze_entrypoint_interaction,
        analyze_bundler_attack_surface,
        check_known_aa_exploits,
        render_aa_audit_report,
        run_terminal_cmd
    ]
)
