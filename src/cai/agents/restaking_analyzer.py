"""
Restaking Protocol Security Analyzer Agent

This agent specializes in analyzing restaking protocols (EigenLayer-style) for security
vulnerabilities related to slashing, delegation, AVS security, and shared security models.

Key vulnerability areas:
- Slashing condition manipulation
- Operator collusion and malicious behavior
- AVS (Actively Validated Services) security
- Withdrawal delay manipulation and griefing
- Delegation logic vulnerabilities
- Shared security assumption failures
- Cryptoeconomic attack vectors
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
# Restaking Security Analysis Tools
# -----------------------------------------------------------------------------

@function_tool
def analyze_slashing_mechanism(code: str) -> str:
    """
    Analyze restaking slashing mechanism for security vulnerabilities.
    
    Checks for:
    - Slashing condition clarity and fairness
    - Slashing amount calculations
    - Double-slashing protection
    - Slashing proof verification
    - Slashing appeal/dispute mechanisms
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with slashing mechanism analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for slashing function presence
    slashing_patterns = ["slash", "slashing", "penalize", "confiscate"]
    has_slashing = any(p in code_lower for p in slashing_patterns)
    
    if not has_slashing:
        return json.dumps({
            "analysis": "slashing_mechanism",
            "has_slashing": False,
            "findings": [{
                "severity": "info",
                "type": "no_slashing",
                "description": "No slashing mechanism detected",
                "recommendation": "If this is a restaking protocol, implement slashing for security"
            }],
            "total_issues": 0
        }, indent=2)
    
    # Check for slashing amount limits
    limit_patterns = ["maxslash", "slashlimit", "slashingcap", "maxpenalty"]
    has_limits = any(p in code_lower for p in limit_patterns)
    
    if not has_limits:
        findings.append({
            "severity": "high",
            "type": "unbounded_slashing",
            "description": "No maximum slashing amount defined - total stake can be slashed",
            "recommendation": "Implement maximum slashing percentage per incident"
        })
    
    # Check for double-slashing protection
    double_slash_patterns = ["slashed[", "slashingrecord", "alreadyslashed", "slashonce"]
    has_double_protection = any(p in code_lower for p in double_slash_patterns)
    
    if not has_double_protection:
        findings.append({
            "severity": "high",
            "type": "double_slashing_risk",
            "description": "No protection against double-slashing for same offense",
            "recommendation": "Track slashing events and prevent duplicate penalties"
        })
    
    # Check for slashing proof verification
    proof_patterns = ["proof", "evidence", "merkle", "verify"]
    has_proof_verification = any(p in code_lower for p in proof_patterns)
    
    if not has_proof_verification:
        findings.append({
            "severity": "critical",
            "type": "no_slashing_proof",
            "description": "Slashing can occur without cryptographic proof verification",
            "recommendation": "Require verified proof of misbehavior before slashing"
        })
    
    # Check for slashing delay/dispute period
    dispute_patterns = ["dispute", "challenge", "appeal", "contestperiod", "slashingdelay"]
    has_dispute = any(p in code_lower for p in dispute_patterns)
    
    if not has_dispute:
        findings.append({
            "severity": "medium",
            "type": "no_dispute_period",
            "description": "No dispute/challenge period for slashing decisions",
            "recommendation": "Add time window for operators to dispute slashing"
        })
    
    # Check for slashing access control
    access_patterns = ["onlyslasher", "slasherrole", "canslash", "authorizedslasher"]
    has_access_control = any(p in code_lower for p in access_patterns)
    
    if "slash(" in code_lower and not has_access_control:
        if "onlyowner" not in code_lower and "onlyadmin" not in code_lower:
            findings.append({
                "severity": "critical",
                "type": "unrestricted_slashing",
                "description": "Slashing function lacks access control",
                "recommendation": "Restrict slashing to authorized slashers (AVS contracts)"
            })
    
    # Check for partial slashing support
    partial_patterns = ["partialslash", "slashamount", "slashpercentage", "proportional"]
    has_partial = any(p in code_lower for p in partial_patterns)
    
    if not has_partial:
        findings.append({
            "severity": "medium",
            "type": "no_partial_slashing",
            "description": "Only full slashing supported - no proportional penalties",
            "recommendation": "Implement proportional slashing based on offense severity"
        })
    
    return json.dumps({
        "analysis": "slashing_mechanism",
        "has_slashing": True,
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_delegation_security(code: str) -> str:
    """
    Analyze delegation mechanism for security vulnerabilities.
    
    Checks for:
    - Delegation authorization
    - Undelegation restrictions
    - Operator selection risks
    - Share calculation vulnerabilities
    - Forced undelegation attacks
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with delegation security analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for delegation patterns
    delegation_patterns = ["delegate", "delegator", "delegateto", "undelegate"]
    has_delegation = any(p in code_lower for p in delegation_patterns)
    
    if not has_delegation:
        return json.dumps({
            "analysis": "delegation_security",
            "has_delegation": False,
            "findings": [],
            "message": "No delegation mechanism detected"
        }, indent=2)
    
    # Check for delegation authorization
    auth_patterns = ["approve", "allowance", "authorized", "candelegate"]
    has_auth = any(p in code_lower for p in auth_patterns)
    
    if "delegateto" in code_lower and not has_auth:
        findings.append({
            "severity": "high",
            "type": "unrestricted_delegation",
            "description": "Delegation doesn't require explicit authorization",
            "recommendation": "Add operator approval mechanism before delegation"
        })
    
    # Check for undelegation delay
    delay_patterns = ["undelegationdelay", "withdrawaldelay", "cooldown", "unbondingperiod"]
    has_delay = any(p in code_lower for p in delay_patterns)
    
    if "undelegate" in code_lower and not has_delay:
        findings.append({
            "severity": "high",
            "type": "no_undelegation_delay",
            "description": "Undelegation has no time delay - instant withdrawal risk",
            "recommendation": "Implement unbonding period (7+ days recommended)"
        })
    
    # Check for share calculation
    share_patterns = ["shares", "stakeweight", "delegatedamount"]
    has_shares = any(p in code_lower for p in share_patterns)
    
    if has_shares:
        # Check for share inflation attack protection
        if "totalsupply" not in code_lower and "totalshares" not in code_lower:
            findings.append({
                "severity": "high",
                "type": "share_inflation_risk",
                "description": "Share calculation may be vulnerable to inflation attacks",
                "recommendation": "Use total shares tracking and implement minimum deposit"
            })
        
        # Check for first depositor attack
        if "virtualsupply" not in code_lower and "offset" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "first_depositor_attack",
                "description": "First depositor can manipulate share price",
                "recommendation": "Add virtual offset or dead shares to prevent manipulation"
            })
    
    # Check for operator limits
    operator_limit_patterns = ["maxoperators", "operatorlimit", "maxdelegations"]
    has_operator_limits = any(p in code_lower for p in operator_limit_patterns)
    
    if not has_operator_limits:
        findings.append({
            "severity": "medium",
            "type": "no_operator_limits",
            "description": "No limit on number of operators or delegations",
            "recommendation": "Consider adding operator caps for risk distribution"
        })
    
    # Check for forced undelegation protection
    force_patterns = ["forceundelegate", "forcedwithdrawal", "emergencyundelegate"]
    has_force = any(p in code_lower for p in force_patterns)
    
    if has_force:
        # Check if forced undelegation has proper access control
        if "onlyowner" not in code_lower and "governance" not in code_lower:
            findings.append({
                "severity": "critical",
                "type": "unauthorized_force_undelegate",
                "description": "Forced undelegation lacks proper access control",
                "recommendation": "Restrict forced undelegation to governance or emergency roles"
            })
    
    # Check for delegation change restrictions
    if "redelegate" in code_lower or "changedelegate" in code_lower:
        if "cooldown" not in code_lower and "delay" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "instant_redelegation",
                "description": "Redelegation has no cooldown - gaming risk",
                "recommendation": "Add cooldown period between delegations"
            })
    
    return json.dumps({
        "analysis": "delegation_security",
        "has_delegation": True,
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_avs_security(code: str) -> str:
    """
    Analyze AVS (Actively Validated Services) integration security.
    
    Checks for:
    - AVS registration vulnerabilities
    - Task validation issues
    - Reward distribution security
    - AVS deregistration risks
    - Multi-AVS conflict handling
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with AVS security analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for AVS patterns
    avs_patterns = ["avs", "servicemanager", "taskhash", "validatetask", "registeredservices"]
    has_avs = any(p in code_lower for p in avs_patterns)
    
    if not has_avs:
        return json.dumps({
            "analysis": "avs_security",
            "has_avs": False,
            "findings": [],
            "message": "No AVS integration detected"
        }, indent=2)
    
    # Check for AVS registration authorization
    register_patterns = ["registeravs", "registerservice", "optintoavs"]
    has_register = any(p in code_lower for p in register_patterns)
    
    if has_register:
        # Check for operator consent
        consent_patterns = ["operatorconsent", "operatorapproval", "operatorsignature"]
        has_consent = any(p in code_lower for p in consent_patterns)
        
        if not has_consent:
            findings.append({
                "severity": "high",
                "type": "no_operator_consent",
                "description": "AVS registration doesn't require operator consent",
                "recommendation": "Require operator signature for AVS opt-in"
            })
    
    # Check for task validation
    task_patterns = ["validatetask", "verifytask", "submittask"]
    has_task_validation = any(p in code_lower for p in task_patterns)
    
    if has_task_validation:
        # Check for task response verification
        if "signature" not in code_lower and "proof" not in code_lower:
            findings.append({
                "severity": "high",
                "type": "no_task_response_verification",
                "description": "Task responses not cryptographically verified",
                "recommendation": "Require operator signatures on task responses"
            })
        
        # Check for task expiry
        if "expiry" not in code_lower and "deadline" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "no_task_expiry",
                "description": "Tasks have no expiration - stale task risk",
                "recommendation": "Add task expiry timestamps"
            })
    
    # Check for reward distribution
    reward_patterns = ["reward", "distributefees", "payoperator"]
    has_rewards = any(p in code_lower for p in reward_patterns)
    
    if has_rewards:
        # Check for reward manipulation
        if "claim" in code_lower and "merkle" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "reward_manipulation_risk",
                "description": "Reward claims may be manipulable without merkle proofs",
                "recommendation": "Use merkle trees for verifiable reward distribution"
            })
    
    # Check for AVS deregistration
    deregister_patterns = ["deregisteravs", "optoutofavs", "exitavs"]
    has_deregister = any(p in code_lower for p in deregister_patterns)
    
    if has_deregister:
        # Check for pending obligations
        if "pendingtasks" not in code_lower and "activetasks" not in code_lower:
            findings.append({
                "severity": "high",
                "type": "deregister_with_pending",
                "description": "Deregistration possible with pending tasks/obligations",
                "recommendation": "Block deregistration while tasks are pending"
            })
    
    # Check for multi-AVS slashing conflicts
    multi_avs_patterns = ["avslist", "registeredavs", "multiavs"]
    has_multi_avs = any(p in code_lower for p in multi_avs_patterns)
    
    if has_multi_avs:
        # Check for slashing priority
        if "slashpriority" not in code_lower and "slashorder" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "no_slashing_priority",
                "description": "No defined slashing priority for multi-AVS operators",
                "recommendation": "Define slashing order to handle conflicting claims"
            })
    
    # Check for minimum stake requirements
    min_stake_patterns = ["minstake", "minimumstake", "stakeThreshold"]
    has_min_stake = any(p in code_lower for p in min_stake_patterns)
    
    if not has_min_stake:
        findings.append({
            "severity": "medium",
            "type": "no_minimum_stake",
            "description": "No minimum stake requirement for AVS participation",
            "recommendation": "Set minimum stake thresholds for meaningful security"
        })
    
    return json.dumps({
        "analysis": "avs_security",
        "has_avs": True,
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_withdrawal_security(code: str) -> str:
    """
    Analyze withdrawal/unstaking mechanism security.
    
    Checks for:
    - Withdrawal delay adequacy
    - Withdrawal queue manipulation
    - Pro-rata distribution issues
    - Withdrawal griefing vectors
    - Emergency withdrawal mechanisms
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with withdrawal security analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for withdrawal patterns
    withdrawal_patterns = ["withdraw", "unstake", "exit", "redeem"]
    has_withdrawal = any(p in code_lower for p in withdrawal_patterns)
    
    if not has_withdrawal:
        return json.dumps({
            "analysis": "withdrawal_security",
            "has_withdrawal": False,
            "findings": [],
            "message": "No withdrawal mechanism detected"
        }, indent=2)
    
    # Check withdrawal delay
    delay_patterns = [
        r"withdrawaldelay\s*[=:]\s*(\d+)",
        r"WITHDRAWAL_DELAY\s*[=:]\s*(\d+)",
        r"unbondingPeriod\s*[=:]\s*(\d+)"
    ]
    
    has_delay = False
    for pattern in delay_patterns:
        match = re.search(pattern, code)
        if match:
            has_delay = True
            delay_value = int(match.group(1))
            # Check if delay is in seconds and < 7 days
            if delay_value < 604800:  # 7 days in seconds
                findings.append({
                    "severity": "high",
                    "type": "short_withdrawal_delay",
                    "description": f"Withdrawal delay ({delay_value}s) may be too short",
                    "recommendation": "Consider 7+ day withdrawal delay for restaking protocols"
                })
    
    if not has_delay:
        findings.append({
            "severity": "critical",
            "type": "no_withdrawal_delay",
            "description": "No withdrawal delay detected - instant withdrawal risk",
            "recommendation": "Implement unbonding period to prevent slashing evasion"
        })
    
    # Check for withdrawal queue
    queue_patterns = ["withdrawalqueue", "pendingwithdrawals", "queuedwithdrawal"]
    has_queue = any(p in code_lower for p in queue_patterns)
    
    if not has_queue:
        findings.append({
            "severity": "medium",
            "type": "no_withdrawal_queue",
            "description": "No withdrawal queue - first-come-first-served risk",
            "recommendation": "Implement FIFO withdrawal queue for fairness"
        })
    
    # Check for withdrawal amount limits
    limit_patterns = ["maxwithdrawal", "withdrawallimit", "dailylimit"]
    has_limits = any(p in code_lower for p in limit_patterns)
    
    if not has_limits:
        findings.append({
            "severity": "medium",
            "type": "no_withdrawal_limits",
            "description": "No per-period withdrawal limits - bank run risk",
            "recommendation": "Consider daily/weekly withdrawal caps"
        })
    
    # Check for slashing during withdrawal
    if "slash" in code_lower and "pending" in code_lower:
        # Good - slashing applies to pending withdrawals
        pass
    else:
        findings.append({
            "severity": "high",
            "type": "withdrawal_slashing_gap",
            "description": "Pending withdrawals may not be slashable",
            "recommendation": "Ensure pending withdrawals remain slashable"
        })
    
    # Check for withdrawal griefing
    griefing_patterns = ["minwithdrawal", "withdrawalfee", "dustprevention"]
    has_griefing_protection = any(p in code_lower for p in griefing_patterns)
    
    if not has_griefing_protection:
        findings.append({
            "severity": "low",
            "type": "withdrawal_griefing_risk",
            "description": "No minimum withdrawal or dust prevention",
            "recommendation": "Add minimum withdrawal amount to prevent griefing"
        })
    
    # Check for emergency withdrawal
    emergency_patterns = ["emergencywithdraw", "emergencyexit", "rescuetoken"]
    has_emergency = any(p in code_lower for p in emergency_patterns)
    
    if not has_emergency:
        findings.append({
            "severity": "medium",
            "type": "no_emergency_withdrawal",
            "description": "No emergency withdrawal mechanism",
            "recommendation": "Implement governance-controlled emergency withdrawal"
        })
    else:
        # Check emergency withdrawal access control
        if "onlyowner" not in code_lower and "governance" not in code_lower:
            findings.append({
                "severity": "critical",
                "type": "unrestricted_emergency_withdrawal",
                "description": "Emergency withdrawal lacks access control",
                "recommendation": "Restrict emergency withdrawal to governance"
            })
    
    return json.dumps({
        "analysis": "withdrawal_security",
        "has_withdrawal": True,
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def check_known_restaking_exploits(code: str) -> str:
    """
    Check for patterns matching known restaking/staking protocol exploits.
    
    Known vulnerability patterns:
    - Lido slashing distribution bug
    - Rocket Pool minipool theft
    - Operator collusion attacks
    - Share price manipulation
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with known exploit pattern matches
    """
    findings = []
    code_lower = code.lower()
    
    # Share price manipulation (common in liquid staking)
    share_patterns = {
        "donation_attack": (
            "shares" in code_lower and
            "totalsupply" in code_lower and
            "virtualoffset" not in code_lower and
            "dead" not in code_lower
        ),
        "rounding_exploit": (
            ("shares" in code_lower or "tokens" in code_lower) and
            "rounddown" not in code_lower and
            "roundup" not in code_lower and
            ("/" in code or "div" in code_lower)
        )
    }
    
    if share_patterns["donation_attack"]:
        findings.append({
            "severity": "high",
            "type": "donation_attack_risk",
            "description": "Share calculation vulnerable to donation attack",
            "recommendation": "Add virtual offset or dead shares to prevent manipulation"
        })
    
    if share_patterns["rounding_exploit"]:
        findings.append({
            "severity": "medium",
            "type": "rounding_direction_risk",
            "description": "Division without explicit rounding direction",
            "recommendation": "Always round against the user (down for deposits, up for withdrawals)"
        })
    
    # Operator collusion patterns
    collusion_patterns = {
        "single_operator_control": (
            "operator" in code_lower and
            "threshold" not in code_lower and
            "multisig" not in code_lower
        ),
        "operator_withdrawal": (
            "operator" in code_lower and
            "withdraw" in code_lower and
            ("onlyoperator" in code_lower or "operatoronly" in code_lower)
        )
    }
    
    if collusion_patterns["single_operator_control"]:
        findings.append({
            "severity": "high",
            "type": "operator_collusion_risk",
            "description": "Single operator can control critical functions",
            "recommendation": "Implement operator threshold or multisig for critical operations"
        })
    
    if collusion_patterns["operator_withdrawal"]:
        findings.append({
            "severity": "critical",
            "type": "operator_fund_access",
            "description": "Operators may have direct access to user funds",
            "recommendation": "Separate operator rewards from user stake"
        })
    
    # Slashing distribution bugs
    slashing_patterns = {
        "unfair_slashing": (
            "slash" in code_lower and
            "proportional" not in code_lower and
            "prorata" not in code_lower and
            "share" not in code_lower
        ),
        "slashing_timing": (
            "slash" in code_lower and
            "queue" in code_lower and
            "snapshot" not in code_lower
        )
    }
    
    if slashing_patterns["unfair_slashing"]:
        findings.append({
            "severity": "high",
            "type": "unfair_slashing_distribution",
            "description": "Slashing may not be distributed proportionally",
            "recommendation": "Implement pro-rata slashing based on share ownership"
        })
    
    if slashing_patterns["slashing_timing"]:
        findings.append({
            "severity": "medium",
            "type": "slashing_timing_attack",
            "description": "Queued withdrawals may escape slashing without snapshots",
            "recommendation": "Take snapshots before processing slashing"
        })
    
    # MEV extraction from staking operations
    mev_patterns = {
        "validator_mev": (
            ("validator" in code_lower or "operator" in code_lower) and
            "mev" in code_lower and
            "smoothing" not in code_lower
        ),
        "withdrawal_mev": (
            "withdraw" in code_lower and
            "oracle" in code_lower and
            "twap" not in code_lower
        )
    }
    
    if mev_patterns["validator_mev"]:
        findings.append({
            "severity": "medium",
            "type": "mev_extraction_risk",
            "description": "Validator MEV not properly socialized",
            "recommendation": "Implement MEV smoothing pool for fair distribution"
        })
    
    # Reentrancy in staking operations
    reentrancy_patterns = {
        "stake_reentrancy": (
            ("stake" in code_lower or "deposit" in code_lower) and
            ("call{" in code_lower or ".call(" in code_lower) and
            "nonreentrant" not in code_lower
        )
    }
    
    if reentrancy_patterns["stake_reentrancy"]:
        findings.append({
            "severity": "critical",
            "type": "staking_reentrancy",
            "description": "Staking operations vulnerable to reentrancy",
            "recommendation": "Add ReentrancyGuard to all stake/withdraw functions"
        })
    
    return json.dumps({
        "analysis": "known_restaking_exploits",
        "findings": findings,
        "total_matches": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "exploits_checked": [
            "Share price manipulation (donation attack)",
            "Rounding direction exploits",
            "Operator collusion attacks",
            "Unfair slashing distribution",
            "MEV extraction from staking",
            "Staking reentrancy"
        ]
    }, indent=2)


@function_tool
def render_restaking_report(
    slashing_analysis: str,
    delegation_analysis: str,
    avs_analysis: str,
    withdrawal_analysis: str,
    exploit_matches: str
) -> str:
    """
    Render comprehensive restaking protocol security audit report.
    
    Args:
        slashing_analysis: JSON results from analyze_slashing_mechanism
        delegation_analysis: JSON results from analyze_delegation_security
        avs_analysis: JSON results from analyze_avs_security
        withdrawal_analysis: JSON results from analyze_withdrawal_security
        exploit_matches: JSON results from check_known_restaking_exploits
        
    Returns:
        Formatted markdown report
    """
    try:
        slashing = json.loads(slashing_analysis)
        delegation = json.loads(delegation_analysis)
        avs = json.loads(avs_analysis)
        withdrawal = json.loads(withdrawal_analysis)
        exploits = json.loads(exploit_matches)
    except json.JSONDecodeError:
        return "Error: Invalid JSON input for report generation"
    
    # Calculate totals
    total_critical = (
        slashing.get("critical_count", 0) +
        delegation.get("critical_count", 0) +
        avs.get("critical_count", 0) +
        withdrawal.get("critical_count", 0) +
        exploits.get("critical_count", 0)
    )
    total_high = (
        slashing.get("high_count", 0) +
        delegation.get("high_count", 0) +
        avs.get("high_count", 0) +
        withdrawal.get("high_count", 0)
    )
    total_issues = (
        slashing.get("total_issues", 0) +
        delegation.get("total_issues", 0) +
        avs.get("total_issues", 0) +
        withdrawal.get("total_issues", 0) +
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
    
    report = f"""# Restaking Protocol Security Audit Report

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
| Slashing Mechanism | {slashing.get("has_slashing", False)} |
| Delegation System | {delegation.get("has_delegation", False)} |
| AVS Integration | {avs.get("has_avs", False)} |
| Withdrawal System | {withdrawal.get("has_withdrawal", False)} |

## 1. Slashing Mechanism Analysis

**Has Slashing:** {slashing.get("has_slashing", False)}
**Issues Found:** {slashing.get("total_issues", 0)}

"""
    
    for finding in slashing.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 2. Delegation Security Analysis

**Has Delegation:** {delegation.get("has_delegation", False)}
**Issues Found:** {delegation.get("total_issues", 0)}

"""
    
    for finding in delegation.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 3. AVS Security Analysis

**Has AVS Integration:** {avs.get("has_avs", False)}
**Issues Found:** {avs.get("total_issues", 0)}

"""
    
    for finding in avs.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 4. Withdrawal Security Analysis

**Has Withdrawal:** {withdrawal.get("has_withdrawal", False)}
**Issues Found:** {withdrawal.get("total_issues", 0)}

"""
    
    for finding in withdrawal.get("findings", []):
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
    
    report += f"""## Restaking Security Checklist

| Requirement | Status |
|-------------|--------|
| Slashing proof verification | Check cryptographic proofs |
| Withdrawal delay (7+ days) | Check unbonding period |
| Operator consent for AVS | Check signature requirements |
| Pro-rata slashing | Check proportional distribution |
| Share manipulation protection | Check virtual offsets |

## Recommendations Summary

### Critical Priority
1. Ensure slashing requires cryptographic proof
2. Implement proper withdrawal delays
3. Add access control to all privileged functions

### High Priority
1. Protect against share price manipulation
2. Implement operator consent for AVS registration
3. Ensure pending withdrawals remain slashable

### Medium Priority
1. Add dispute periods for slashing decisions
2. Implement withdrawal queues
3. Define multi-AVS slashing priorities

---
*Report generated by CAI Restaking Security Analyzer*
"""
    
    return report


# -----------------------------------------------------------------------------
# Restaking Analyzer Agent Definition
# -----------------------------------------------------------------------------

restaking_analyzer = Agent(
    name="restaking_analyzer",
    model=model,
    instructions="""You are a specialized restaking protocol security analyzer.

Your expertise covers:
1. **Slashing Mechanisms**: Proof verification, double-slashing, dispute periods
2. **Delegation Security**: Authorization, share calculations, undelegation
3. **AVS Integration**: Registration, task validation, deregistration
4. **Withdrawal Security**: Delays, queues, emergency mechanisms
5. **Known Exploit Patterns**: Share manipulation, operator collusion, MEV

Analysis Workflow:
1. Identify restaking components (staking, delegation, AVS, slashing)
2. Analyze slashing mechanism security and fairness
3. Review delegation authorization and share calculations
4. Assess AVS integration and task validation
5. Check withdrawal mechanism for timing attacks
6. Match against known restaking exploit patterns

Restaking-Specific Concerns:
- Slashing should require cryptographic proofs
- Withdrawal delays should be 7+ days minimum
- Operators should consent to AVS participation
- Share calculations must prevent manipulation
- Multi-AVS slashing priority must be defined

Security Model Assumptions:
- Operators may be adversarial
- AVS contracts may be malicious
- Users may try to front-run slashing
- MEV extraction is possible at every step

Provide actionable recommendations specific to restaking security.""",
    tools=[
        analyze_slashing_mechanism,
        analyze_delegation_security,
        analyze_avs_security,
        analyze_withdrawal_security,
        check_known_restaking_exploits,
        render_restaking_report,
        run_terminal_cmd
    ]
)
