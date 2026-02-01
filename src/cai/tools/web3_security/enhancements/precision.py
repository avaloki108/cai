"""
Precision Loss Detector

Detects division-before-multiplication, rounding direction exploitation,
dust amount attacks, and semantic-aware overflow/underflow in unchecked blocks.
"""

import json
from typing import List, Dict, Any, Optional, Tuple
from cai.sdk.agents import function_tool


@function_tool
def analyze_precision_vulnerabilities(
    solidity_code: str, strict_mode: bool = False
) -> str:
    """
    Analyze Solidity code for precision-related vulnerabilities.

    Args:
        solidity_code: The Solidity contract source code
        strict_mode: If True, flag all potential issues; if False, flag only high-confidence issues

    Returns:
        JSON string with precision vulnerability findings
    """
    findings = []

    # Detect division before multiplication
    div_before_mult = _detect_division_before_multiplication(solidity_code, strict_mode)
    if div_before_mult["findings"]:
        findings.append(div_before_mult)

    # Detect rounding direction exploitation
    rounding_issues = _detect_rounding_exploitation(solidity_code, strict_mode)
    if rounding_issues["findings"]:
        findings.append(rounding_issues)

    # Detect dust amount attacks
    dust_issues = _detect_dust_attacks(solidity_code, strict_mode)
    if dust_issues["findings"]:
        findings.append(dust_issues)

    # Detect semantic-aware overflow in unchecked blocks
    overflow_issues = _detect_semantic_overflow(solidity_code, strict_mode)
    if overflow_issues["findings"]:
        findings.append(overflow_issues)

    result = {
        "vulnerability_type": "precision_loss",
        "total_issues": sum(cat["issue_count"] for cat in findings),
        "categories": findings,
        "severity": _calculate_overall_severity(findings),
    }

    return json.dumps(result, indent=2)


def _detect_division_before_multiplication(
    code: str, strict_mode: bool
) -> Dict[str, Any]:
    """
    Detect patterns where division occurs before multiplication,
    causing precision loss.

    Vulnerable pattern: result = x / y * z
    Better pattern: result = x * z / y

    Common in DeFi:
    - shares = amount * totalShares / totalAssets (vulnerable: amount / totalAssets * totalShares)
    - reward = balance * rewardPerShare (vulnerable: balance * rewardPerShare / precision)
    """
    import re

    findings = []
    patterns = [
        # Division before multiplication in arithmetic operations
        r"(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)",
        # Assignment with div then mult
        r"(\w+)\s*=\s*(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)",
        # Function calls with div before mult
        r"(\w+\([^)]*\))\s*/\s*(\w+)\s*\*\s*(\w+)",
        # Complex expressions: a / b * c * d
        r"(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)\s*\*\s*(\w+)",
    ]

    for pattern in patterns:
        matches = re.finditer(pattern, code, re.MULTILINE)

        for match in matches:
            line_num = code[: match.start()].count("\n") + 1
            matched_text = match.group(0)

            # Extract context
            context_start = max(0, match.start() - 100)
            context_end = min(len(code), match.end() + 100)
            context = code[context_start:context_end]

            # Check if this is a known pattern from vault/share calculations
            is_vault_calc = any(
                keyword in context.lower()
                for keyword in [
                    "share",
                    "vault",
                    "totalassets",
                    "totalsupply",
                    "convert",
                    "deposit",
                    "withdraw",
                ]
            )

            # Check if this is a known pattern from reward calculations
            is_reward_calc = any(
                keyword in context.lower()
                for keyword in [
                    "reward",
                    "stake",
                    "claim",
                    "distribute",
                    "perblock",
                    "pertoken",
                ]
            )

            severity = "high" if (is_vault_calc or is_reward_calc) else "medium"

            finding = {
                "issue_type": "division_before_multiplication",
                "line": line_num,
                "code": matched_text,
                "context": context.strip(),
                "severity": severity,
                "description": "Division before multiplication causes precision loss",
                "recommendation": "Multiply first, then divide: (x * z) / y instead of x / y * z",
                "impact": "Precision loss can lead to value leakage, especially with repeated operations",
            }
            findings.append(finding)

    return {
        "category": "division_before_multiplication",
        "description": "Operations where division precedes multiplication",
        "issue_count": len(findings),
        "findings": findings,
    }


def _detect_rounding_exploitation(code: str, strict_mode: bool) -> Dict[str, Any]:
    """
    Detect rounding direction exploitation where one party benefits
    from rounding down vs rounding up.

    Common exploitable patterns:
    - ERC4626 shares: always round down favors depositors
    - Transfer fees: always round down favors sender
    - Reward distribution: rounding direction determines beneficiary
    """
    import re

    findings = []

    # Pattern 1: share calculation with division (common in vaults)
    share_patterns = [
        r"shares\s*=\s*amount\s*\*\s*totalShares\s*/\s*totalAssets",
        r"shares\s*=\s*amount\s*\*\s*(1e18)\s*/\s*(\w+)",
        r"mint\s*\(\s*.*\s*shares\s*=\s*.*\*/\s*.*\)",
    ]

    # Pattern 2: fee calculation with division
    fee_patterns = [
        r"fee\s*=\s*amount\s*\*\s*(\d+)\s*/\s*(1e\d+)",
        r"fee\s*=\s*amount\s*/\s*(\d+)",
    ]

    # Pattern 3: reward distribution
    reward_patterns = [
        r"reward\s*=\s*balance\s*\*\s*rewardPerShare\s*/\s*(1e\d+)",
        r"shareReward\s*=\s*totalReward\s*/\s*totalShares",
    ]

    all_patterns = [
        ("share_calculation", share_patterns, "ERC4626-style share calculation"),
        ("fee_calculation", fee_patterns, "Fee calculation"),
        ("reward_calculation", reward_patterns, "Reward distribution"),
    ]

    for pattern_type, patterns, description in all_patterns:
        for pattern in patterns:
            matches = re.finditer(pattern, code, re.MULTILINE)

            for match in matches:
                line_num = code[: match.start()].count("\n") + 1
                matched_text = match.group(0)

                # Extract context to understand function
                context_start = max(0, match.start() - 150)
                context_end = min(len(code), match.end() + 150)
                context = code[context_start:context_end]

                # Determine who benefits from rounding
                if pattern_type == "share_calculation":
                    # Check if deposit or mint
                    if "deposit" in context.lower() or "mint" in context.lower():
                        beneficiary = "depositor (rounding down favors first depositor)"
                        severity = "high"
                    elif "withdraw" in context.lower() or "redeem" in context.lower():
                        beneficiary = "protocol (rounding down on withdraw favors last withdrawer)"
                        severity = "high"
                    else:
                        beneficiary = "unknown - check function semantics"
                        severity = "medium"
                elif pattern_type == "fee_calculation":
                    beneficiary = "sender (rounding down reduces fee)"
                    severity = "medium"
                elif pattern_type == "reward_calculation":
                    beneficiary = "protocol (rounding down reduces payout)"
                    severity = "medium"
                else:
                    beneficiary = "unknown"
                    severity = "medium"

                # Check for explicit rounding control
                has_rounding_control = "ceil" in context or "round" in context

                finding = {
                    "issue_type": "rounding_direction_exploitation",
                    "line": line_num,
                    "code": matched_text,
                    "context": context.strip(),
                    "severity": severity,
                    "category": pattern_type,
                    "description": f"{description} with implicit rounding",
                    "beneficiary": beneficiary,
                    "has_explicit_rounding": has_rounding_control,
                    "recommendation": "Document rounding direction or use consistent rounding (e.g., Math.ceil for user-favorable, Math.floor for protocol-protection)",
                    "impact": "Rounding direction determines who loses or gains value in fractional transactions",
                }
                findings.append(finding)

    # Pattern 4: Asymmetric rounding (different directions for different operations)
    # Check for ceil in one place and floor (or no rounding) in another
    ceil_count = len(re.findall(r"\.ceil\s*\(", code))
    floor_count = len(re.findall(r"\.floor\s*\(", code))

    if ceil_count > 0 and floor_count == 0:
        findings.append(
            {
                "issue_type": "asymmetric_rounding",
                "line": 0,
                "code": "Multiple rounding functions detected",
                "context": f"ceil used {ceil_count} times, floor used {floor_count} times",
                "severity": "low" if not strict_mode else "medium",
                "description": "Potential asymmetric rounding across operations",
                "beneficiary": "depends on function semantics",
                "recommendation": "Document rounding policy or ensure consistent direction",
                "impact": "Asymmetric rounding can create arbitrage opportunities",
            }
        )

    return {
        "category": "rounding_exploitation",
        "description": "Rounding direction determines beneficiary",
        "issue_count": len(findings),
        "findings": findings,
    }


def _detect_dust_attacks(code: str, strict_mode: bool) -> Dict[str, Any]:
    """
    Detect dust amount attacks where small amounts (< minUnit)
    cause unexpected behavior or bypass checks.

    Common dust attack vectors:
    - Min deposit/withdraw thresholds
    - Zero checks that don't account for dust
    - Approval/transfer of dust amounts
    - State changes triggered by dust deposits
    """
    import re

    findings = []

    # Pattern 1: Minimum amount thresholds
    min_amount_patterns = [
        r"require\s*\(\s*amount\s*>\s*(\d+|MIN_AMOUNT|MIN_DEPOSIT)\s*\)",
        r"require\s*\(\s*amount\s*>=\s*(\d+|MIN_AMOUNT|MIN_DEPOSIT)\s*\)",
        r"if\s*\(\s*amount\s*<\s*(\d+|MIN_AMOUNT|MIN_DEPOSIT)\s*\)",
    ]

    # Pattern 2: Zero checks (dust bypass)
    zero_check_patterns = [
        r"require\s*\(\s*amount\s*>\s*0\s*\)",
        r"require\s*\(\s*amount\s*!=\s*0\s*\)",
        r"if\s*\(\s*amount\s*==\s*0\s*\)",
    ]

    # Pattern 3: Fee calculations that might produce dust
    fee_patterns = [
        r"fee\s*=\s*amount\s*\*\s*(\d+)\s*/\s*(1e\d+)",
        r"fee\s*=\s*amount\s*/\s*(\d+)",
    ]

    all_patterns = [
        ("min_amount_threshold", min_amount_patterns, "Minimum amount threshold"),
        ("zero_check", zero_check_patterns, "Zero check (dust bypass)"),
        ("fee_dust", fee_patterns, "Fee calculation (may produce dust)"),
    ]

    for pattern_type, patterns, description in all_patterns:
        for pattern in patterns:
            matches = re.finditer(pattern, code, re.MULTILINE)

            for match in matches:
                line_num = code[: match.start()].count("\n") + 1
                matched_text = match.group(0)

                # Extract context
                context_start = max(0, match.start() - 150)
                context_end = min(len(code), match.end() + 150)
                context = code[context_start:context_end]

                # Analyze specific risks
                risk_analysis = []
                bypass_potential = False

                if pattern_type == "min_amount_threshold":
                    # Extract the threshold value
                    threshold_match = re.search(
                        r"(\d+|MIN_AMOUNT|MIN_DEPOSIT)", matched_text
                    )
                    threshold = (
                        threshold_match.group(1) if threshold_match else "unknown"
                    )

                    if threshold == "0":
                        bypass_potential = True
                        risk_analysis.append(
                            "Threshold is 0 - dust amounts bypass minimum"
                        )
                    elif threshold.isdigit() and int(threshold) < 100:
                        bypass_potential = True
                        risk_analysis.append(
                            f"Threshold ({threshold}) is very low - dust amounts may bypass"
                        )

                elif pattern_type == "zero_check":
                    bypass_potential = True
                    risk_analysis.append(
                        "Zero checks allow any non-zero amount, including dust"
                    )

                    # Check if this zero check guards critical state changes
                    if "deposit" in context.lower() or "stake" in context.lower():
                        risk_analysis.append("Dust deposit can trigger state changes")
                    if "vote" in context.lower() or "propose" in context.lower():
                        risk_analysis.append(
                            "Dust amounts might trigger governance actions"
                        )
                    if "claim" in context.lower():
                        risk_analysis.append("Dust amounts might claim rewards")

                elif pattern_type == "fee_dust":
                    # Check if fee is subtracted and not checked
                    if re.search(r"amount\s*-\s*fee", context):
                        risk_analysis.append(
                            "Fee subtraction might leave dust in user balance"
                        )
                        bypass_potential = True

                # Check if dust can trigger state changes
                state_triggers = [
                    "balanceOf",
                    "totalSupply",
                    "reward",
                    "deposit",
                    "withdraw",
                    "stake",
                    "unstake",
                    "claim",
                    "vote",
                    "propose",
                    "transfer",
                    "mint",
                    "burn",
                ]

                triggers_state = any(
                    trigger in context.lower() for trigger in state_triggers
                )

                severity = "high" if (bypass_potential and triggers_state) else "medium"

                finding = {
                    "issue_type": "dust_amount_attack",
                    "line": line_num,
                    "code": matched_text,
                    "context": context.strip(),
                    "severity": severity,
                    "category": pattern_type,
                    "description": f"{description} vulnerable to dust amounts",
                    "bypass_potential": bypass_potential,
                    "triggers_state_changes": triggers_state,
                    "risk_analysis": risk_analysis,
                    "recommendation": "Use meaningful minimum thresholds (e.g., >= 1e12 for wei) or round up dust amounts",
                    "impact": "Dust amounts can bypass minimum checks, trigger state changes, or accumulate into significant losses",
                }
                findings.append(finding)

    # Pattern 4: Missing dust check in critical operations
    # Look for functions that handle amounts without minimum checks
    critical_functions = [
        (r"function\s+(deposit|stake|mint|addLiquidity)", "Critical deposit function"),
        (
            r"function\s+(withdraw|unstake|redeem|removeLiquidity)",
            "Critical withdraw function",
        ),
    ]

    for func_pattern, func_desc in critical_functions:
        func_matches = re.finditer(func_pattern, code, re.MULTILINE)

        for func_match in func_matches:
            # Find function body (simplified - actual AST parsing would be better)
            func_start = func_match.start()
            func_end = code.find("}", func_match.end() + 100)  # Look ahead

            if func_end == -1:
                continue

            func_body = code[func_start:func_end]

            # Check if amount check is present
            has_min_check = bool(
                re.search(r"require\s*\(\s*amount\s*[>=<>]", func_body)
            )

            if not has_min_check and strict_mode:
                line_num = code[:func_start].count("\n") + 1
                findings.append(
                    {
                        "issue_type": "missing_dust_check",
                        "line": line_num,
                        "code": func_match.group(0),
                        "context": func_desc,
                        "severity": "medium",
                        "description": f"{func_desc} without minimum amount check",
                        "bypass_potential": True,
                        "triggers_state_changes": True,
                        "recommendation": "Add require(amount >= MIN_AMOUNT) to prevent dust transactions",
                        "impact": "Dust amounts can trigger state changes without meaningful value",
                    }
                )

    return {
        "category": "dust_amount_attacks",
        "description": "Dust amounts (< minUnit) bypassing checks or triggering state changes",
        "issue_count": len(findings),
        "findings": findings,
    }


def _detect_semantic_overflow(code: str, strict_mode: bool) -> Dict[str, Any]:
    """
    Detect overflow/underflow in unchecked blocks with semantic awareness.

    Key differences from standard overflow detection:
    - Understand when overflow is intended vs exploitable
    - Check if bounds checking occurs before arithmetic
    - Detect operations where semantic logic prevents overflow vs doesn't
    """
    import re

    findings = []

    # Pattern 1: Unchecked arithmetic that could overflow
    # Note: Solidity 0.8+ has built-in overflow checks, so we focus on:
    # - Explicit unchecked blocks
    # - Semantic overflow (logical bounds exceeded)
    # - Accumulation patterns

    unchecked_patterns = [
        # Addition in unchecked block
        r"unchecked\s*\{[^}]*\w+\s*\+\s*\w+",
        # Multiplication in unchecked block
        r"unchecked\s*\{[^}]*\w+\s*\*\s*\w+",
        # Compound operations
        r"unchecked\s*\{[^}]*totalAmount\s*\+\s*newAmount",
    ]

    for pattern in unchecked_patterns:
        matches = re.finditer(pattern, code, re.MULTILINE)

        for match in matches:
            line_num = code[: match.start()].count("\n") + 1
            matched_text = match.group(0)

            # Extract the unchecked block content
            block_match = re.search(r"unchecked\s*\{([^}]*)\}", matched_text)
            if not block_match:
                continue

            block_content = block_match.group(1)

            # Analyze the arithmetic operation
            op_type = "unknown"
            if "+" in block_content:
                op_type = "addition"
            elif "*" in block_content:
                op_type = "multiplication"
            elif "-" in block_content:
                op_type = "subtraction"
            elif "/" in block_content:
                op_type = "division"

            # Check if there's bounds checking before or after
            context_start = max(0, match.start() - 200)
            context_end = min(len(code), match.end() + 200)
            context = code[context_start:context_end]

            has_bounds_check = bool(
                re.search(r"require\s*\(\s*\w+\s*[<>=]+\s*\w+\s*\)", context)
            )

            # Semantic analysis: is overflow expected or exploitable?
            semantic_risk = _analyze_semantic_overflow_risk(block_content, context)

            # Determine severity
            if semantic_risk["risk_level"] == "high":
                severity = "high"
            elif semantic_risk["risk_level"] == "medium":
                severity = "medium"
            else:
                severity = "low" if not strict_mode else "medium"

            finding = {
                "issue_type": "semantic_overflow_in_unchecked",
                "line": line_num,
                "code": matched_text,
                "context": context.strip(),
                "severity": severity,
                "operation_type": op_type,
                "has_bounds_check": has_bounds_check,
                "semantic_risk": semantic_risk,
                "recommendation": semantic_risk.get(
                    "recommendation", "Review unchecked arithmetic for overflow risk"
                ),
                "impact": semantic_risk.get(
                    "impact",
                    "Overflow in unchecked blocks can cause undefined behavior or value manipulation",
                ),
            }
            findings.append(finding)

    # Pattern 2: Accumulation overflow (repeated additions)
    accumulation_patterns = [
        # Accumulating balances or totals
        r"totalBalance\s*\+=\s*amount",
        r"totalSupply\s*\+=\s*amount",
        r"cumulativeReward\s*\+=\s*reward",
        # Loop accumulation
        r"for\s*\([^)]*\)\s*\{[^}]*total\s*\+=",
    ]

    for pattern in accumulation_patterns:
        matches = re.finditer(pattern, code, re.MULTILINE)

        for match in matches:
            line_num = code[: match.start()].count("\n") + 1
            matched_text = match.group(0)

            context_start = max(0, match.start() - 150)
            context_end = min(len(code), match.end() + 150)
            context = code[context_start:context_end]

            # Check if this is in a loop
            in_loop = "for" in context or "while" in context

            # Check if there's any bounds checking
            has_bounds_check = bool(
                re.search(r"require\s*\(\s*total.*<\s*\w+\s*\)", context)
            )

            # Semantic analysis
            semantic_risk = _analyze_semantic_overflow_risk(matched_text, context)

            if semantic_risk["risk_level"] != "low" or strict_mode:
                finding = {
                    "issue_type": "accumulation_overflow",
                    "line": line_num,
                    "code": matched_text,
                    "context": context.strip(),
                    "severity": "high" if in_loop else "medium",
                    "in_loop": in_loop,
                    "has_bounds_check": has_bounds_check,
                    "semantic_risk": semantic_risk,
                    "recommendation": "Add explicit overflow protection or use checked arithmetic",
                    "impact": "Repeated accumulation can exceed type bounds, especially in loops",
                }
                findings.append(finding)

    # Pattern 3: Multiplication of large numbers
    multiplication_patterns = [
        r"(\w+)\s*\*\s*(\w+)\s*\*\s*(\w+)",  # Triple multiplication
        r"amount\s*\*\s*precision\s*\*\s*factor",
        r"totalReward\s*\*\s*rewardPerToken",
    ]

    for pattern in multiplication_patterns:
        matches = re.finditer(pattern, code, re.MULTILINE)

        for match in matches:
            line_num = code[: match.start()].count("\n") + 1
            matched_text = match.group(0)

            context_start = max(0, match.start() - 100)
            context_end = min(len(code), match.end() + 100)
            context = code[context_start:context_end]

            # Count multiplications
            mult_count = matched_text.count("*")

            semantic_risk = {
                "risk_level": "high" if mult_count >= 3 else "medium",
                "reason": f"{mult_count} consecutive multiplications increase overflow probability",
                "recommendation": "Add bounds checks before multiplication or use SafeMath",
                "impact": "Large number multiplication can easily exceed uint256 bounds",
            }

            finding = {
                "issue_type": "multiplication_overflow",
                "line": line_num,
                "code": matched_text,
                "context": context.strip(),
                "severity": "high" if mult_count >= 3 else "medium",
                "multiplication_count": mult_count,
                "semantic_risk": semantic_risk,
                "recommendation": "Check bounds before multiplying: require(a <= type(uint256).max / b)",
                "impact": "Multiplication of large values can overflow, causing value distortion",
            }
            findings.append(finding)

    return {
        "category": "semantic_overflow",
        "description": "Overflow/underflow with semantic awareness of intent vs exploitability",
        "issue_count": len(findings),
        "findings": findings,
    }


def _analyze_semantic_overflow_risk(operation: str, context: str) -> Dict[str, Any]:
    """
    Analyze whether an overflow is semantically intended or exploitable.

    Returns risk assessment with:
    - risk_level: "low", "medium", "high"
    - reason: Explanation of the risk
    - recommendation: Specific mitigation
    - impact: Potential consequences
    """
    risk_level = "low"
    reason = ""
    recommendation = ""
    impact = ""

    # Check for protective patterns (overflow is intended or prevented)
    protective_keywords = ["wrapping", "modulo", "cycle", "roll", "%", "&"]
    has_protection = any(kw in operation.lower() for kw in protective_keywords)

    # Check for dangerous patterns (overflow is exploitable)
    dangerous_keywords = [
        "balance",
        "total",
        "amount",
        "reward",
        "deposit",
        "withdraw",
        "transfer",
    ]
    is_dangerous = any(kw in operation.lower() for kw in dangerous_keywords)

    # Check for bounds checking in context
    has_bounds_check = bool(
        re.search(r"require\s*\(\s*\w+\s*[<>=]+\s*\w+\s*\)", context)
    )

    # Check for type casting
    has_cast = bool(re.search(r"(uint|int)\d+\s*\(", operation))

    # Determine risk
    if has_protection:
        risk_level = "low"
        reason = "Overflow appears intentional (wrapping/modulo behavior)"
        recommendation = "Document intentional overflow for clarity"
        impact = "Overflow is by design, not a vulnerability"

    elif is_dangerous and not has_bounds_check:
        risk_level = "high"
        reason = "Operation on critical financial values without bounds checking"
        recommendation = "Add require checks before arithmetic or use SafeMath"
        impact = "Overflow can corrupt balances, rewards, or totals"

    elif is_dangerous and has_bounds_check:
        risk_level = "medium"
        reason = "Operation on critical values with bounds checking"
        recommendation = "Verify bounds are sufficient to prevent overflow"
        impact = "Bounds check may be insufficient for all edge cases"

    elif has_cast:
        risk_level = "medium"
        reason = "Type casting may cause truncation or overflow"
        recommendation = "Verify cast is safe or add explicit checks"
        impact = "Type casting can change value semantics"

    else:
        risk_level = "low"
        reason = "No obvious overflow risk detected"
        recommendation = "Review if bounds are appropriate"
        impact = "Unclear - manual review recommended"

    return {
        "risk_level": risk_level,
        "reason": reason,
        "recommendation": recommendation,
        "impact": impact,
    }


def _calculate_overall_severity(findings: List[Dict[str, Any]]) -> str:
    """
    Calculate overall severity based on all findings.

    Returns: "critical", "high", "medium", "low", or "none"
    """
    if not findings:
        return "none"

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for category in findings:
        for finding in category["findings"]:
            severity = finding.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1

    # Determine overall severity
    if severity_counts["critical"] > 0:
        return "critical"
    elif severity_counts["high"] >= 2:
        return "critical"
    elif severity_counts["high"] > 0:
        return "high"
    elif severity_counts["medium"] >= 3:
        return "high"
    elif severity_counts["medium"] > 0:
        return "medium"
    elif severity_counts["low"] > 0:
        return "low"
    else:
        return "none"
