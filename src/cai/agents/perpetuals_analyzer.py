"""
Perpetuals Protocol Analyzer

Specialized analyzer for perpetual futures/derivatives protocols.
Detects vulnerabilities specific to perps trading platforms.

Key Attack Vectors:
- Funding rate manipulation
- Liquidation cascade attacks
- Price manipulation via oracle
- Position size manipulation
- Margin calculation errors
- Insurance fund drainage
"""

import os
import json
import re
from typing import Dict, Any, List
from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool

load_dotenv()

api_key = (
    os.getenv("OPENAI_API_KEY")
    or os.getenv("ANTHROPIC_API_KEY")
    or os.getenv("ALIAS_API_KEY")
    or "sk-placeholder"
)


@function_tool
def analyze_funding_rate(contract_code: str, ctf=None) -> str:
    """
    Analyze funding rate mechanism for manipulation vulnerabilities.
    
    Args:
        contract_code: Source code of the perpetuals contract
        
    Returns:
        Funding rate analysis
    """
    findings = []
    
    # Check for funding rate calculation
    has_funding = bool(re.search(r'fundingRate|funding_rate|getFunding', contract_code, re.IGNORECASE))
    has_twap = bool(re.search(r'twap|timeWeighted|TWAP', contract_code, re.IGNORECASE))
    has_cap = bool(re.search(r'maxFundingRate|fundingCap|MAX_FUNDING', contract_code, re.IGNORECASE))
    has_interval = bool(re.search(r'fundingInterval|FUNDING_PERIOD', contract_code, re.IGNORECASE))
    
    if has_funding and not has_twap:
        findings.append({
            "issue": "SPOT_PRICE_FUNDING",
            "severity": "HIGH",
            "description": "Funding rate uses spot price instead of TWAP - vulnerable to manipulation",
            "recommendation": "Use time-weighted average price for funding calculations"
        })
    
    if has_funding and not has_cap:
        findings.append({
            "issue": "UNCAPPED_FUNDING",
            "severity": "MEDIUM",
            "description": "No maximum funding rate cap - extreme rates possible",
            "recommendation": "Implement funding rate caps (e.g., 0.1% per hour)"
        })
    
    if not has_interval:
        findings.append({
            "issue": "NO_FUNDING_INTERVAL",
            "severity": "MEDIUM",
            "description": "No defined funding interval - timing attacks possible",
            "recommendation": "Define fixed funding intervals (e.g., 8 hours)"
        })
    
    return json.dumps({
        "analysis_type": "funding_rate",
        "has_funding_mechanism": has_funding,
        "uses_twap": has_twap,
        "has_rate_cap": has_cap,
        "has_interval": has_interval,
        "findings": findings,
        "risk_level": "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM" if findings else "LOW"
    }, indent=2)


@function_tool
def analyze_liquidation_mechanism(contract_code: str, ctf=None) -> str:
    """
    Analyze liquidation mechanism for cascade and manipulation risks.
    
    Args:
        contract_code: Source code of the perpetuals contract
        
    Returns:
        Liquidation analysis
    """
    findings = []
    
    # Check liquidation components
    has_liquidation = bool(re.search(r'liquidate|liquidation', contract_code, re.IGNORECASE))
    has_partial_liquidation = bool(re.search(r'partialLiquidate|liquidatePartial|partialClose', contract_code, re.IGNORECASE))
    has_liquidation_fee = bool(re.search(r'liquidationFee|liquidatorReward|LIQUIDATION_FEE', contract_code, re.IGNORECASE))
    has_insurance_fund = bool(re.search(r'insuranceFund|insurance_fund|INSURANCE', contract_code, re.IGNORECASE))
    has_adl = bool(re.search(r'autoDeleverage|ADL|socialized', contract_code, re.IGNORECASE))
    
    if has_liquidation and not has_partial_liquidation:
        findings.append({
            "issue": "NO_PARTIAL_LIQUIDATION",
            "severity": "HIGH",
            "description": "No partial liquidation - large positions can cause cascade",
            "recommendation": "Implement partial liquidation to reduce market impact"
        })
    
    if has_liquidation and not has_insurance_fund:
        findings.append({
            "issue": "NO_INSURANCE_FUND",
            "severity": "CRITICAL",
            "description": "No insurance fund - bad debt directly impacts traders",
            "recommendation": "Implement insurance fund for bad debt coverage"
        })
    
    if not has_adl:
        findings.append({
            "issue": "NO_ADL_MECHANISM",
            "severity": "MEDIUM",
            "description": "No auto-deleveraging mechanism for extreme scenarios",
            "recommendation": "Implement ADL for insurance fund protection"
        })
    
    # Check for liquidation price manipulation
    has_mark_price = bool(re.search(r'markPrice|mark_price|getMarkPrice', contract_code, re.IGNORECASE))
    if not has_mark_price:
        findings.append({
            "issue": "NO_MARK_PRICE",
            "severity": "HIGH",
            "description": "No mark price for liquidations - index manipulation risk",
            "recommendation": "Use mark price (index + funding) for liquidation triggers"
        })
    
    return json.dumps({
        "analysis_type": "liquidation_mechanism",
        "has_liquidation": has_liquidation,
        "has_partial_liquidation": has_partial_liquidation,
        "has_insurance_fund": has_insurance_fund,
        "has_adl": has_adl,
        "has_mark_price": has_mark_price,
        "findings": findings,
        "risk_level": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM" if findings else "LOW"
    }, indent=2)


@function_tool
def analyze_margin_system(contract_code: str, ctf=None) -> str:
    """
    Analyze margin and collateral system for vulnerabilities.
    
    Args:
        contract_code: Source code of the perpetuals contract
        
    Returns:
        Margin system analysis
    """
    findings = []
    
    # Check margin components
    has_margin = bool(re.search(r'margin|collateral', contract_code, re.IGNORECASE))
    has_cross_margin = bool(re.search(r'crossMargin|cross_margin', contract_code, re.IGNORECASE))
    has_isolated = bool(re.search(r'isolatedMargin|isolated_margin', contract_code, re.IGNORECASE))
    has_maintenance = bool(re.search(r'maintenanceMargin|maintenance_margin|MM_RATIO', contract_code, re.IGNORECASE))
    has_initial = bool(re.search(r'initialMargin|initial_margin|IM_RATIO', contract_code, re.IGNORECASE))
    
    if has_margin and not has_maintenance:
        findings.append({
            "issue": "NO_MAINTENANCE_MARGIN",
            "severity": "CRITICAL",
            "description": "No maintenance margin requirement - positions can go deeply negative",
            "recommendation": "Implement maintenance margin ratio (e.g., 0.5-1%)"
        })
    
    if has_margin and not has_initial:
        findings.append({
            "issue": "NO_INITIAL_MARGIN",
            "severity": "HIGH",
            "description": "No initial margin requirement - excessive leverage possible",
            "recommendation": "Implement initial margin ratio for position opening"
        })
    
    # Check for leverage limits
    has_max_leverage = bool(re.search(r'maxLeverage|MAX_LEVERAGE|leverage.*limit', contract_code, re.IGNORECASE))
    if not has_max_leverage:
        findings.append({
            "issue": "NO_LEVERAGE_LIMIT",
            "severity": "HIGH",
            "description": "No maximum leverage limit - systemic risk",
            "recommendation": "Implement maximum leverage (e.g., 100x)"
        })
    
    return json.dumps({
        "analysis_type": "margin_system",
        "has_margin": has_margin,
        "has_cross_margin": has_cross_margin,
        "has_isolated": has_isolated,
        "has_maintenance": has_maintenance,
        "has_initial": has_initial,
        "has_max_leverage": has_max_leverage,
        "findings": findings,
        "risk_level": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "LOW"
    }, indent=2)


@function_tool
def analyze_position_management(contract_code: str, ctf=None) -> str:
    """
    Analyze position management for manipulation vulnerabilities.
    
    Args:
        contract_code: Source code of the perpetuals contract
        
    Returns:
        Position management analysis
    """
    findings = []
    
    # Check position limits
    has_position_limit = bool(re.search(r'maxPosition|positionLimit|MAX_POSITION', contract_code, re.IGNORECASE))
    has_oi_limit = bool(re.search(r'maxOpenInterest|openInterestLimit|MAX_OI', contract_code, re.IGNORECASE))
    has_size_check = bool(re.search(r'minPositionSize|MIN_SIZE|positionSize.*require', contract_code, re.IGNORECASE))
    
    if not has_position_limit:
        findings.append({
            "issue": "NO_POSITION_LIMIT",
            "severity": "HIGH",
            "description": "No per-account position limit - whale manipulation risk",
            "recommendation": "Implement maximum position size per account"
        })
    
    if not has_oi_limit:
        findings.append({
            "issue": "NO_OI_LIMIT",
            "severity": "MEDIUM",
            "description": "No open interest limit - market can become illiquid",
            "recommendation": "Implement maximum open interest relative to liquidity"
        })
    
    # Check for position ordering
    has_fifo = bool(re.search(r'FIFO|firstInFirstOut|positionQueue', contract_code, re.IGNORECASE))
    
    return json.dumps({
        "analysis_type": "position_management",
        "has_position_limit": has_position_limit,
        "has_oi_limit": has_oi_limit,
        "has_size_check": has_size_check,
        "has_fifo": has_fifo,
        "findings": findings,
        "risk_level": "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM" if findings else "LOW"
    }, indent=2)


@function_tool
def render_perpetuals_report(
    contract_name: str,
    funding_findings: List[Dict],
    liquidation_findings: List[Dict],
    margin_findings: List[Dict],
    position_findings: List[Dict],
    ctf=None
) -> str:
    """
    Render comprehensive perpetuals security report.
    """
    all_findings = funding_findings + liquidation_findings + margin_findings + position_findings
    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    
    report = f"""# Perpetuals Protocol Security Report

## Contract: {contract_name}

### Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {critical} |
| HIGH | {high} |
| MEDIUM | {len(all_findings) - critical - high} |

**Overall Risk: {'CRITICAL' if critical > 0 else 'HIGH' if high > 0 else 'MEDIUM' if all_findings else 'LOW'}**

---

### 1. Funding Rate Analysis
"""
    
    if funding_findings:
        for f in funding_findings:
            report += f"- **[{f['severity']}]** {f['issue']}: {f['description']}\n"
    else:
        report += "No funding rate issues found.\n"
    
    report += "\n### 2. Liquidation Mechanism\n"
    if liquidation_findings:
        for f in liquidation_findings:
            report += f"- **[{f['severity']}]** {f['issue']}: {f['description']}\n"
    else:
        report += "No liquidation issues found.\n"
    
    report += "\n### 3. Margin System\n"
    if margin_findings:
        for f in margin_findings:
            report += f"- **[{f['severity']}]** {f['issue']}: {f['description']}\n"
    else:
        report += "No margin system issues found.\n"
    
    report += "\n### 4. Position Management\n"
    if position_findings:
        for f in position_findings:
            report += f"- **[{f['severity']}]** {f['issue']}: {f['description']}\n"
    else:
        report += "No position management issues found.\n"
    
    report += """
---

### Recommendations

1. Implement TWAP-based funding rate calculations
2. Use partial liquidations to prevent cascade effects
3. Maintain adequate insurance fund for bad debt
4. Implement mark price for liquidation triggers
5. Set appropriate leverage and position limits

*Generated by CAI Perpetuals Analyzer*
"""
    
    return report


PERPETUALS_PROMPT = """You are the PERPETUALS ANALYZER - Expert in perpetual futures protocol security.

## Your Mission

Identify vulnerabilities in perpetual futures/derivatives protocols that could lead to:
- Funding rate manipulation
- Liquidation cascades
- Bad debt accumulation
- Insurance fund drainage
- Position manipulation

## Key Attack Vectors

### 1. Funding Rate Attacks
- Manipulate spot price to affect funding
- Exploit funding rate timing
- Game funding calculations

### 2. Liquidation Attacks
- Trigger cascade liquidations
- Manipulate mark/index price
- Front-run liquidations

### 3. Margin Attacks
- Exploit margin calculation errors
- Leverage limit bypass
- Cross-margin contagion

### 4. Position Manipulation
- Whale position attacks
- Open interest manipulation
- Order book attacks

## Your Tools

- `analyze_funding_rate` - Check funding mechanism
- `analyze_liquidation_mechanism` - Audit liquidation system
- `analyze_margin_system` - Review margin/collateral
- `analyze_position_management` - Check position limits
- `render_perpetuals_report` - Generate report

Remember: Perps vulnerabilities can cause massive losses through cascading liquidations.
"""

perpetuals_analyzer_tools = [
    analyze_funding_rate,
    analyze_liquidation_mechanism,
    analyze_margin_system,
    analyze_position_management,
    render_perpetuals_report,
]

perpetuals_analyzer = Agent(
    name="Perpetuals Analyzer",
    instructions=PERPETUALS_PROMPT,
    description="""Specialized analyzer for perpetual futures protocol security.
    Detects funding rate manipulation, liquidation cascade risks, margin system
    vulnerabilities, and position management issues.""",
    tools=perpetuals_analyzer_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['perpetuals_analyzer']
