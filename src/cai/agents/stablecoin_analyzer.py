"""
Stablecoin Protocol Security Analyzer Agent

This agent specializes in analyzing stablecoin protocols for security vulnerabilities
related to peg stability, collateralization, liquidation mechanisms, and algorithmic
stability designs.

Key vulnerability areas:
- Depeg risks (collateralization ratios, liquidation cascades)
- Oracle manipulation affecting peg stability
- Bank run scenarios and liquidity crises
- Algorithmic stability mechanism flaws (rebase, elastic supply)
- Governance attacks on critical parameters
- Interest rate manipulation for CDP-style stablecoins
- Flash loan attacks on stability mechanisms
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
# Stablecoin Security Analysis Tools
# -----------------------------------------------------------------------------

@function_tool
def analyze_collateralization(code: str) -> str:
    """
    Analyze stablecoin collateralization mechanism for security vulnerabilities.
    
    Checks for:
    - Insufficient collateral ratio requirements
    - Missing or flawed collateral ratio calculations
    - Unsafe collateral types
    - Collateral valuation vulnerabilities
    - Flash loan collateral manipulation
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with collateralization analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for collateral ratio definitions
    collateral_patterns = {
        "minimum_ratio": r"(minCollateral|minRatio|minimumCollateral|collateralRatio|MIN_COLLATERAL|COLLATERALIZATION_RATIO)\s*[=:]\s*(\d+)",
        "ratio_check": r"(require|assert|if)\s*\([^)]*collateral[^)]*ratio",
        "collateral_value": r"(getCollateralValue|collateralValue|calculateCollateral)",
    }
    
    ratio_matches = re.findall(collateral_patterns["minimum_ratio"], code)
    if not ratio_matches:
        findings.append({
            "severity": "high",
            "type": "missing_collateral_ratio",
            "description": "No explicit minimum collateralization ratio defined",
            "recommendation": "Define explicit minimum collateralization ratio (typically 150%+ for CDP stablecoins)"
        })
    else:
        for match in ratio_matches:
            ratio_value = int(match[1]) if match[1].isdigit() else 0
            if ratio_value > 0 and ratio_value < 110:
                findings.append({
                    "severity": "critical",
                    "type": "insufficient_collateral_ratio",
                    "description": f"Collateralization ratio {ratio_value}% is dangerously low",
                    "recommendation": "Increase minimum collateralization ratio to at least 150%"
                })
    
    # Check for collateral ratio validation
    if not re.search(collateral_patterns["ratio_check"], code_lower):
        findings.append({
            "severity": "high",
            "type": "missing_ratio_check",
            "description": "No collateral ratio validation found",
            "recommendation": "Add require statements to enforce minimum collateralization"
        })
    
    # Check for unsafe collateral handling
    unsafe_patterns = [
        (r"msg\.value\s*>\s*0", "direct_eth_collateral", "Direct ETH collateral without price oracle"),
        (r"transferFrom[^;]*collateral", "unchecked_transfer", "Collateral transfer without balance verification"),
    ]
    
    for pattern, vuln_type, desc in unsafe_patterns:
        if re.search(pattern, code):
            # Check if there's proper validation
            if "oracle" not in code_lower or "getPrice" not in code:
                findings.append({
                    "severity": "medium",
                    "type": vuln_type,
                    "description": desc,
                    "recommendation": "Use price oracle for collateral valuation"
                })
    
    # Check for flash loan protection
    if "collateral" in code_lower:
        flash_protection_patterns = [
            "block.number", "block.timestamp", "delay", "timelock", "cooldown"
        ]
        has_protection = any(p in code_lower for p in flash_protection_patterns)
        if not has_protection:
            findings.append({
                "severity": "high",
                "type": "no_flash_loan_protection",
                "description": "Collateral operations lack flash loan protection",
                "recommendation": "Add block number checks or time delays to prevent flash loan manipulation"
            })
    
    return json.dumps({
        "analysis": "collateralization_security",
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_liquidation_mechanism(code: str) -> str:
    """
    Analyze stablecoin liquidation mechanism for security vulnerabilities.
    
    Checks for:
    - Liquidation threshold issues
    - Oracle manipulation in liquidations
    - Liquidation incentive problems
    - Cascade liquidation risks
    - Bad debt handling
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with liquidation analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for liquidation threshold
    if "liquidat" in code_lower:
        # Check for liquidation threshold definition
        threshold_patterns = [
            r"liquidationThreshold\s*[=:]\s*(\d+)",
            r"LIQUIDATION_THRESHOLD\s*[=:]\s*(\d+)",
            r"liquidationRatio\s*[=:]\s*(\d+)"
        ]
        
        has_threshold = False
        for pattern in threshold_patterns:
            match = re.search(pattern, code)
            if match:
                has_threshold = True
                threshold_value = int(match.group(1))
                if threshold_value < 100:
                    findings.append({
                        "severity": "critical",
                        "type": "invalid_liquidation_threshold",
                        "description": f"Liquidation threshold {threshold_value}% below 100% allows under-collateralized debt",
                        "recommendation": "Set liquidation threshold above 100%"
                    })
        
        if not has_threshold:
            findings.append({
                "severity": "high",
                "type": "missing_liquidation_threshold",
                "description": "No explicit liquidation threshold defined",
                "recommendation": "Define explicit liquidation threshold constant"
            })
        
        # Check for liquidation incentive/bonus
        bonus_patterns = [
            "liquidationBonus", "liquidationIncentive", "liquidatorReward",
            "LIQUIDATION_BONUS", "LIQUIDATOR_INCENTIVE"
        ]
        has_bonus = any(p in code for p in bonus_patterns)
        if not has_bonus:
            findings.append({
                "severity": "medium",
                "type": "missing_liquidation_incentive",
                "description": "No liquidation incentive found - may discourage liquidators",
                "recommendation": "Add liquidation bonus to incentivize timely liquidations"
            })
        
        # Check for partial liquidation support
        partial_patterns = ["partialLiquidation", "maxLiquidation", "liquidationLimit"]
        has_partial = any(p in code for p in partial_patterns)
        if not has_partial and "liquidat" in code_lower:
            findings.append({
                "severity": "medium",
                "type": "no_partial_liquidation",
                "description": "Full liquidation only - increases cascade liquidation risk",
                "recommendation": "Implement partial liquidation to reduce systemic risk"
            })
        
        # Check for bad debt handling
        bad_debt_patterns = ["badDebt", "bad_debt", "shortfall", "deficit", "insuranceFund"]
        has_bad_debt_handling = any(p in code for p in bad_debt_patterns)
        if not has_bad_debt_handling:
            findings.append({
                "severity": "high",
                "type": "no_bad_debt_handling",
                "description": "No bad debt handling mechanism found",
                "recommendation": "Implement insurance fund or socialized loss mechanism for bad debt"
            })
        
        # Check for oracle usage in liquidation
        if "oracle" not in code_lower and "getPrice" not in code:
            findings.append({
                "severity": "critical",
                "type": "no_oracle_in_liquidation",
                "description": "Liquidation logic doesn't appear to use price oracle",
                "recommendation": "Use reliable price oracle (Chainlink) for liquidation decisions"
            })
    else:
        findings.append({
            "severity": "info",
            "type": "no_liquidation_mechanism",
            "description": "No liquidation mechanism detected",
            "recommendation": "If this is a collateralized stablecoin, implement liquidation mechanism"
        })
    
    return json.dumps({
        "analysis": "liquidation_security",
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_peg_stability(code: str) -> str:
    """
    Analyze stablecoin peg stability mechanisms for vulnerabilities.
    
    Checks for:
    - Algorithmic stability flaws (rebase, elastic supply)
    - Arbitrage mechanism issues
    - PSM (Peg Stability Module) vulnerabilities
    - Interest rate manipulation
    - Governance attack vectors on stability parameters
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with peg stability analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Detect stablecoin type
    is_algorithmic = any(p in code_lower for p in ["rebase", "elastic", "expand", "contract", "epoch"])
    is_cdp = any(p in code_lower for p in ["collateral", "vault", "cdp", "debt"])
    is_psm = any(p in code_lower for p in ["psm", "pegstability", "swap"])
    
    # Algorithmic stablecoin checks
    if is_algorithmic:
        # Check for bounded expansion/contraction
        bound_patterns = ["maxExpansion", "maxContraction", "expansionLimit", "MAX_SUPPLY_CHANGE"]
        has_bounds = any(p in code for p in bound_patterns)
        if not has_bounds:
            findings.append({
                "severity": "critical",
                "type": "unbounded_supply_change",
                "description": "No bounds on algorithmic supply expansion/contraction",
                "recommendation": "Add maximum supply change limits per epoch"
            })
        
        # Check for TWAP usage
        if "twap" not in code_lower and "timeweight" not in code_lower:
            findings.append({
                "severity": "high",
                "type": "no_twap_pricing",
                "description": "Algorithmic stablecoin doesn't use TWAP for price",
                "recommendation": "Use time-weighted average price to resist manipulation"
            })
        
        # Check for death spiral protection
        death_spiral_patterns = ["debtCeiling", "floorPrice", "recoveryMode", "emergencyShutdown"]
        has_protection = any(p in code for p in death_spiral_patterns)
        if not has_protection:
            findings.append({
                "severity": "critical",
                "type": "no_death_spiral_protection",
                "description": "No protection against algorithmic death spiral",
                "recommendation": "Implement floor price, debt ceiling, or emergency shutdown"
            })
    
    # CDP stablecoin checks
    if is_cdp:
        # Check for stability fee
        if "stabilityfee" not in code_lower and "interestrate" not in code_lower and "borrowrate" not in code_lower:
            findings.append({
                "severity": "medium",
                "type": "no_stability_fee",
                "description": "No stability fee mechanism found",
                "recommendation": "Implement stability fee to control stablecoin supply"
            })
        
        # Check for governance time delays on critical params
        critical_params = ["setStabilityFee", "setLiquidationRatio", "setDebtCeiling"]
        has_timelock = "timelock" in code_lower or "delay" in code_lower
        for param in critical_params:
            if param.lower() in code_lower and not has_timelock:
                findings.append({
                    "severity": "high",
                    "type": "no_timelock_on_params",
                    "description": f"Critical parameter {param} lacks timelock protection",
                    "recommendation": "Add timelock delay for governance parameter changes"
                })
                break
    
    # PSM checks
    if is_psm:
        # Check for PSM limits
        if "limit" not in code_lower and "ceiling" not in code_lower and "cap" not in code_lower:
            findings.append({
                "severity": "high",
                "type": "unbounded_psm",
                "description": "PSM has no swap limits",
                "recommendation": "Add daily/total swap limits to PSM"
            })
        
        # Check for PSM fee
        psm_fee_patterns = ["psmFee", "swapFee", "tin", "tout"]
        has_psm_fee = any(p in code for p in psm_fee_patterns)
        if not has_psm_fee:
            findings.append({
                "severity": "medium",
                "type": "no_psm_fee",
                "description": "PSM has no swap fee - vulnerable to free arbitrage attacks",
                "recommendation": "Add small swap fee to discourage manipulation"
            })
    
    # General peg stability checks
    # Check for emergency shutdown
    emergency_patterns = ["emergencyshutdown", "globalshutdown", "cage", "pause"]
    has_emergency = any(p in code_lower for p in emergency_patterns)
    if not has_emergency:
        findings.append({
            "severity": "high",
            "type": "no_emergency_shutdown",
            "description": "No emergency shutdown mechanism found",
            "recommendation": "Implement emergency shutdown for black swan events"
        })
    
    return json.dumps({
        "analysis": "peg_stability_security",
        "stablecoin_type": {
            "algorithmic": is_algorithmic,
            "cdp": is_cdp,
            "psm": is_psm
        },
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def analyze_oracle_dependency(code: str) -> str:
    """
    Analyze stablecoin oracle dependencies for security vulnerabilities.
    
    Checks for:
    - Single oracle dependency
    - Missing staleness checks
    - Oracle manipulation vectors
    - Fallback oracle mechanisms
    - Price deviation protections
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with oracle dependency analysis results
    """
    findings = []
    code_lower = code.lower()
    
    # Check for oracle usage
    oracle_patterns = [
        "oracle", "pricefeed", "chainlink", "getprice", "latestanswer",
        "aggregator", "getrounddata"
    ]
    has_oracle = any(p in code_lower for p in oracle_patterns)
    
    if not has_oracle:
        findings.append({
            "severity": "critical",
            "type": "no_oracle",
            "description": "No price oracle integration detected",
            "recommendation": "Integrate reliable price oracle (Chainlink recommended)"
        })
        return json.dumps({
            "analysis": "oracle_dependency",
            "findings": findings,
            "total_issues": len(findings)
        }, indent=2)
    
    # Check for staleness validation
    staleness_patterns = [
        "updatedat", "timestamp", "stale", "freshness", "maxdelay",
        "heartbeat", "sequenceruptime"
    ]
    has_staleness_check = any(p in code_lower for p in staleness_patterns)
    if not has_staleness_check:
        findings.append({
            "severity": "high",
            "type": "no_staleness_check",
            "description": "Oracle price staleness not validated",
            "recommendation": "Add timestamp check to reject stale prices"
        })
    
    # Check for price deviation protection
    deviation_patterns = [
        "deviation", "maxchange", "pricechange", "circuit", "breaker"
    ]
    has_deviation_check = any(p in code_lower for p in deviation_patterns)
    if not has_deviation_check:
        findings.append({
            "severity": "medium",
            "type": "no_deviation_protection",
            "description": "No price deviation circuit breaker",
            "recommendation": "Add circuit breaker for large price movements"
        })
    
    # Check for fallback oracle
    fallback_patterns = ["fallback", "backup", "secondary", "alternative"]
    has_fallback = any(p in code_lower for p in fallback_patterns)
    if not has_fallback:
        findings.append({
            "severity": "medium",
            "type": "no_fallback_oracle",
            "description": "No fallback oracle mechanism",
            "recommendation": "Implement fallback oracle for resilience"
        })
    
    # Check for single oracle dependency
    oracle_count_patterns = [
        (r"oracle\s*=", 1),
        (r"priceFeed\s*=", 1),
        (r"aggregator\[", 0)  # Array suggests multiple
    ]
    single_oracle_risk = True
    for pattern, indicates_single in oracle_count_patterns:
        matches = re.findall(pattern, code)
        if indicates_single == 0 and matches:
            single_oracle_risk = False
            break
    
    if single_oracle_risk and "median" not in code_lower:
        findings.append({
            "severity": "high",
            "type": "single_oracle_dependency",
            "description": "Single oracle dependency creates single point of failure",
            "recommendation": "Use multiple oracles with median or TWAP aggregation"
        })
    
    # Check for L2-specific oracle issues (sequencer uptime)
    l2_patterns = ["arbitrum", "optimism", "l2", "rollup"]
    is_l2 = any(p in code_lower for p in l2_patterns)
    if is_l2 and "sequencer" not in code_lower:
        findings.append({
            "severity": "high",
            "type": "no_sequencer_check",
            "description": "L2 deployment without sequencer uptime check",
            "recommendation": "Add Chainlink sequencer uptime feed check for L2"
        })
    
    return json.dumps({
        "analysis": "oracle_dependency",
        "findings": findings,
        "total_issues": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"])
    }, indent=2)


@function_tool
def check_known_stablecoin_exploits(code: str) -> str:
    """
    Check for patterns matching known stablecoin exploits.
    
    Known exploit patterns:
    - UST/LUNA death spiral (May 2022) - $40B
    - Beanstalk governance attack (Apr 2022) - $182M
    - Cashio infinite mint (Mar 2022) - $52M
    - Iron Finance bank run (Jun 2021) - $2B TVL
    
    Args:
        code: Smart contract source code to analyze
        
    Returns:
        JSON string with known exploit pattern matches
    """
    findings = []
    code_lower = code.lower()
    
    # UST/LUNA death spiral pattern - algorithmic without backing
    ust_patterns = {
        "algorithmic_no_backing": (
            any(p in code_lower for p in ["rebase", "elastic", "algorithmic"]) and
            not any(p in code_lower for p in ["collateral", "reserve", "backing"])
        ),
        "mint_burn_arbitrage": (
            "mint" in code_lower and "burn" in code_lower and
            not any(p in code_lower for p in ["limit", "cap", "ceiling"])
        ),
        "no_floor_protection": (
            any(p in code_lower for p in ["rebase", "elastic"]) and
            not any(p in code_lower for p in ["floor", "minimum", "recovery"])
        )
    }
    
    if ust_patterns["algorithmic_no_backing"]:
        findings.append({
            "severity": "critical",
            "type": "ust_pattern",
            "exploit_reference": "UST/LUNA Death Spiral (May 2022) - $40B",
            "description": "Algorithmic stablecoin without collateral backing - vulnerable to death spiral",
            "recommendation": "Add collateral reserves or implement robust floor mechanisms"
        })
    
    if ust_patterns["mint_burn_arbitrage"] and ust_patterns["no_floor_protection"]:
        findings.append({
            "severity": "critical",
            "type": "death_spiral_risk",
            "exploit_reference": "Iron Finance (Jun 2021) - $2B TVL drained",
            "description": "Uncapped mint/burn arbitrage without floor protection enables bank run",
            "recommendation": "Add daily limits, circuit breakers, and floor price mechanisms"
        })
    
    # Beanstalk governance attack pattern - flash loan governance
    beanstalk_patterns = {
        "flash_loan_governance": (
            any(p in code_lower for p in ["governance", "vote", "proposal"]) and
            any(p in code_lower for p in ["flash", "borrow"]) or
            ("governance" in code_lower and "snapshot" not in code_lower and "timelock" not in code_lower)
        ),
        "instant_execution": (
            any(p in code_lower for p in ["execute", "proposal"]) and
            not any(p in code_lower for p in ["delay", "timelock", "voting period"])
        )
    }
    
    if beanstalk_patterns["flash_loan_governance"] or beanstalk_patterns["instant_execution"]:
        findings.append({
            "severity": "critical",
            "type": "beanstalk_pattern",
            "exploit_reference": "Beanstalk Governance Attack (Apr 2022) - $182M",
            "description": "Governance vulnerable to flash loan attacks or instant execution",
            "recommendation": "Use snapshot-based voting with timelock delays"
        })
    
    # Cashio infinite mint pattern - missing validation
    cashio_patterns = {
        "unchecked_mint": (
            "mint" in code_lower and
            not re.search(r"require\s*\([^)]*mint", code_lower) and
            not re.search(r"only(owner|admin|minter)", code_lower)
        ),
        "collateral_verification_missing": (
            "collateral" in code_lower and
            "mint" in code_lower and
            not any(p in code_lower for p in ["verify", "validate", "check"])
        )
    }
    
    if cashio_patterns["unchecked_mint"]:
        findings.append({
            "severity": "critical",
            "type": "cashio_pattern",
            "exploit_reference": "Cashio Infinite Mint (Mar 2022) - $52M",
            "description": "Mint function lacks proper access control or validation",
            "recommendation": "Add strict access control and collateral verification for minting"
        })
    
    # Iron Finance bank run pattern - partial collateral + panic
    iron_patterns = {
        "partial_collateral": (
            any(p in code_lower for p in ["partial", "fractional"]) and
            any(p in code_lower for p in ["collateral", "reserve"])
        ),
        "no_redemption_limits": (
            any(p in code_lower for p in ["redeem", "withdraw"]) and
            not any(p in code_lower for p in ["limit", "cap", "delay", "queue"])
        )
    }
    
    if iron_patterns["partial_collateral"] and iron_patterns["no_redemption_limits"]:
        findings.append({
            "severity": "high",
            "type": "iron_finance_pattern",
            "exploit_reference": "Iron Finance Bank Run (Jun 2021)",
            "description": "Fractional reserves without redemption limits - bank run risk",
            "recommendation": "Add redemption queues, limits, or delay mechanisms"
        })
    
    return json.dumps({
        "analysis": "known_stablecoin_exploits",
        "findings": findings,
        "total_matches": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "exploits_checked": [
            "UST/LUNA Death Spiral ($40B)",
            "Beanstalk Governance ($182M)",
            "Cashio Infinite Mint ($52M)",
            "Iron Finance Bank Run ($2B TVL)"
        ]
    }, indent=2)


@function_tool
def render_stablecoin_report(
    collateral_analysis: str,
    liquidation_analysis: str,
    peg_stability_analysis: str,
    oracle_analysis: str,
    exploit_matches: str
) -> str:
    """
    Render comprehensive stablecoin security audit report.
    
    Args:
        collateral_analysis: JSON results from analyze_collateralization
        liquidation_analysis: JSON results from analyze_liquidation_mechanism
        peg_stability_analysis: JSON results from analyze_peg_stability
        oracle_analysis: JSON results from analyze_oracle_dependency
        exploit_matches: JSON results from check_known_stablecoin_exploits
        
    Returns:
        Formatted markdown report
    """
    try:
        collateral = json.loads(collateral_analysis)
        liquidation = json.loads(liquidation_analysis)
        peg = json.loads(peg_stability_analysis)
        oracle = json.loads(oracle_analysis)
        exploits = json.loads(exploit_matches)
    except json.JSONDecodeError:
        return "Error: Invalid JSON input for report generation"
    
    # Calculate totals
    total_critical = (
        collateral.get("critical_count", 0) +
        liquidation.get("critical_count", 0) +
        peg.get("critical_count", 0) +
        oracle.get("critical_count", 0) +
        exploits.get("critical_count", 0)
    )
    total_high = (
        collateral.get("high_count", 0) +
        liquidation.get("high_count", 0) +
        peg.get("high_count", 0) +
        oracle.get("high_count", 0)
    )
    total_issues = (
        collateral.get("total_issues", 0) +
        liquidation.get("total_issues", 0) +
        peg.get("total_issues", 0) +
        oracle.get("total_issues", 0) +
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
    
    report = f"""# Stablecoin Security Audit Report

## Executive Summary

| Metric | Value |
|--------|-------|
| Overall Risk Level | **{risk_level}** |
| Critical Issues | {total_critical} |
| High Issues | {total_high} |
| Total Issues | {total_issues} |

## Stablecoin Type Detection

| Type | Detected |
|------|----------|
| CDP/Collateralized | {peg.get("stablecoin_type", {}).get("cdp", False)} |
| Algorithmic | {peg.get("stablecoin_type", {}).get("algorithmic", False)} |
| PSM-enabled | {peg.get("stablecoin_type", {}).get("psm", False)} |

## 1. Collateralization Analysis

**Issues Found:** {collateral.get("total_issues", 0)}

"""
    
    for finding in collateral.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 2. Liquidation Mechanism Analysis

**Issues Found:** {liquidation.get("total_issues", 0)}

"""
    
    for finding in liquidation.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 3. Peg Stability Analysis

**Issues Found:** {peg.get("total_issues", 0)}

"""
    
    for finding in peg.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 4. Oracle Dependency Analysis

**Issues Found:** {oracle.get("total_issues", 0)}

"""
    
    for finding in oracle.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## 5. Known Exploit Pattern Matches

**Matches Found:** {exploits.get("total_matches", 0)}

**Exploits Checked:**
"""
    for exploit in exploits.get("exploits_checked", []):
        report += f"- {exploit}\n"
    
    report += "\n"
    
    for finding in exploits.get("findings", []):
        report += f"""### [{finding['severity'].upper()}] {finding['type']}
- **Reference:** {finding.get('exploit_reference', 'N/A')}
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}

"""
    
    report += f"""## Recommendations Summary

### Critical Priority
1. Address all critical oracle and collateralization issues immediately
2. Implement death spiral protection mechanisms
3. Add governance timelock and flash loan protection

### High Priority
1. Implement comprehensive liquidation mechanism
2. Add circuit breakers for price deviation
3. Deploy emergency shutdown functionality

### Medium Priority
1. Add fallback oracle mechanisms
2. Implement partial liquidation support
3. Add PSM fees and limits

---
*Report generated by CAI Stablecoin Security Analyzer*
"""
    
    return report


# -----------------------------------------------------------------------------
# Stablecoin Analyzer Agent Definition
# -----------------------------------------------------------------------------

stablecoin_analyzer = Agent(
    name="stablecoin_analyzer",
    model=model,
    instructions="""You are a specialized stablecoin protocol security analyzer.

Your expertise covers:
1. **Collateralization Security**: Analyzing collateral ratios, types, and valuation
2. **Liquidation Mechanisms**: Reviewing liquidation thresholds, incentives, and cascade risks
3. **Peg Stability**: Evaluating algorithmic, CDP, and PSM stability mechanisms
4. **Oracle Dependencies**: Assessing oracle integration and manipulation risks
5. **Known Exploit Patterns**: Matching against historical stablecoin exploits

Analysis Workflow:
1. First, identify the stablecoin type (CDP, algorithmic, PSM, hybrid)
2. Analyze collateralization and liquidation mechanisms
3. Review peg stability design and oracle integrations
4. Check for patterns matching known exploits (UST, Beanstalk, Cashio, Iron Finance)
5. Generate comprehensive security report

Focus Areas:
- Depeg risk assessment
- Death spiral vulnerability detection
- Bank run scenario analysis
- Governance attack vectors
- Flash loan manipulation risks

When analyzing code:
- Look for minimum collateralization ratios (should be 150%+)
- Verify liquidation thresholds and incentives exist
- Check for oracle staleness and deviation protections
- Ensure emergency shutdown mechanisms are present
- Validate governance has appropriate timelocks

Provide actionable recommendations prioritized by severity.""",
    tools=[
        analyze_collateralization,
        analyze_liquidation_mechanism,
        analyze_peg_stability,
        analyze_oracle_dependency,
        check_known_stablecoin_exploits,
        render_stablecoin_report,
        run_terminal_cmd
    ]
)
