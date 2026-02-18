"""
MEV (Maximal Extractable Value) Analyzer Agent

Specialized agent for detecting MEV vulnerabilities and transaction ordering risks.
Focuses on identifying opportunities for sandwich attacks, frontrunning, backrunning,
and other MEV extraction strategies.

Key Attack Vectors:
- Sandwich attacks on DEX swaps
- Frontrunning of profitable transactions
- Backrunning of state-changing transactions
- JIT (Just-In-Time) liquidity attacks
- Time-bandit attacks (reorg-based MEV)
- Oracle update frontrunning

Based on MEV research and observed on-chain extraction patterns.
"""

import os
import json
import re
from typing import Dict, Any, List, Optional
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


# MEV vulnerability patterns
MEV_PATTERNS = {
    "sandwich_vulnerable": {
        "description": "Function vulnerable to sandwich attacks",
        "severity": "HIGH",
        "indicators": ["swap", "exchange", "trade", "amountOutMin"],
        "requires_public_mempool": True,
    },
    "frontrun_vulnerable": {
        "description": "Function can be profitably frontrun",
        "severity": "HIGH",
        "indicators": ["buy", "mint", "claim", "liquidate"],
        "requires_public_mempool": True,
    },
    "backrun_vulnerable": {
        "description": "State change creates backrun opportunity",
        "severity": "MEDIUM",
        "indicators": ["sell", "burn", "withdraw", "updatePrice"],
        "requires_public_mempool": True,
    },
    "oracle_frontrun": {
        "description": "Oracle update can be frontrun",
        "severity": "CRITICAL",
        "indicators": ["updatePrice", "setPrice", "submitAnswer"],
        "requires_public_mempool": True,
    },
}


# Common DEX function signatures
DEX_SIGNATURES = {
    "uniswap_v2": [
        "swapExactTokensForTokens",
        "swapTokensForExactTokens",
        "swapExactETHForTokens",
        "swapTokensForExactETH",
        "swapExactTokensForETH",
        "swapETHForExactTokens",
    ],
    "uniswap_v3": [
        "exactInputSingle",
        "exactInput",
        "exactOutputSingle",
        "exactOutput",
    ],
    "curve": [
        "exchange",
        "exchange_underlying",
    ],
    "balancer": [
        "swap",
        "batchSwap",
    ],
}


@function_tool
def analyze_sandwich_vulnerability(
    contract_code: str,
    function_name: str = "",
    ctf=None
) -> str:
    """
    Analyze contract for sandwich attack vulnerabilities.
    
    Args:
        contract_code: Source code of the contract
        function_name: Specific function to analyze (optional)
        
    Returns:
        Sandwich attack vulnerability analysis
    """
    try:
        findings = []
        
        # Check for swap functions
        has_swap = bool(re.search(r'\bswap\b|\bexchange\b|\btrade\b', contract_code, re.IGNORECASE))
        
        # Check for slippage protection
        has_min_amount = bool(re.search(r'amountOutMin|minAmountOut|minReturn|slippage', contract_code, re.IGNORECASE))
        has_deadline = bool(re.search(r'deadline|expiry|validUntil', contract_code, re.IGNORECASE))
        
        if has_swap and not has_min_amount:
            findings.append({
                "issue": "NO_SLIPPAGE_PROTECTION",
                "severity": "CRITICAL",
                "description": "Swap function lacks minimum output amount - fully vulnerable to sandwich",
                "mev_type": "sandwich",
                "recommendation": "Add amountOutMin parameter and enforce minimum received"
            })
        
        if has_swap and not has_deadline:
            findings.append({
                "issue": "NO_DEADLINE",
                "severity": "HIGH",
                "description": "Swap lacks deadline - transaction can be held and executed at unfavorable time",
                "mev_type": "sandwich",
                "recommendation": "Add deadline parameter and validate block.timestamp <= deadline"
            })
        
        # Check for hardcoded slippage
        hardcoded_slippage = re.search(r'amountOutMin\s*=\s*0|minAmountOut\s*=\s*0', contract_code)
        if hardcoded_slippage:
            findings.append({
                "issue": "ZERO_SLIPPAGE",
                "severity": "CRITICAL",
                "description": "Slippage set to 0 - sandwich attacker can extract full trade value",
                "mev_type": "sandwich",
                "recommendation": "Calculate reasonable minimum based on oracle price"
            })
        
        # Check for price impact calculation
        has_price_impact = bool(re.search(r'priceImpact|getAmountOut|quote', contract_code, re.IGNORECASE))
        
        # Check for private transaction support
        has_private_tx = bool(re.search(r'flashbots|mev-blocker|privateTx|bundleId', contract_code, re.IGNORECASE))
        
        result = {
            "analysis_type": "sandwich_vulnerability",
            "function": function_name or "contract-wide",
            "has_swap_functions": has_swap,
            "has_slippage_protection": has_min_amount,
            "has_deadline": has_deadline,
            "has_price_impact_calc": has_price_impact,
            "supports_private_tx": has_private_tx,
            "findings_count": len(findings),
            "findings": findings,
            "verdict": "PROTECTED" if len(findings) == 0 else "VULNERABLE",
            "estimated_mev_exposure": "HIGH" if not has_min_amount else "MEDIUM" if not has_deadline else "LOW"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing sandwich vulnerability: {str(e)}"})


@function_tool
def analyze_frontrun_vulnerability(
    contract_code: str,
    function_name: str = "",
    ctf=None
) -> str:
    """
    Analyze contract for frontrunning vulnerabilities.
    
    Args:
        contract_code: Source code of the contract
        function_name: Specific function to analyze (optional)
        
    Returns:
        Frontrunning vulnerability analysis
    """
    try:
        findings = []
        
        # Check for profitable operations that can be frontrun
        has_liquidation = bool(re.search(r'\bliquidate\b|\bliquidation\b', contract_code, re.IGNORECASE))
        has_arbitrage = bool(re.search(r'\barbitrage\b|\bprofit\b', contract_code, re.IGNORECASE))
        has_claim = bool(re.search(r'\bclaim\b|\bharvest\b|\bcollect\b', contract_code, re.IGNORECASE))
        has_auction = bool(re.search(r'\bauction\b|\bbid\b', contract_code, re.IGNORECASE))
        
        # Check for commit-reveal scheme
        has_commit_reveal = bool(re.search(r'commit|reveal|hash.*secret', contract_code, re.IGNORECASE))
        
        if has_liquidation and not has_commit_reveal:
            findings.append({
                "issue": "LIQUIDATION_FRONTRUN",
                "severity": "HIGH",
                "description": "Liquidation function can be frontrun by MEV searchers",
                "mev_type": "frontrun",
                "recommendation": "Implement commit-reveal or use Flashbots Protect"
            })
        
        if has_arbitrage:
            findings.append({
                "issue": "ARBITRAGE_EXPOSURE",
                "severity": "MEDIUM",
                "description": "Arbitrage opportunities visible in mempool",
                "mev_type": "frontrun",
                "recommendation": "Use private transaction relays"
            })
        
        if has_auction and not has_commit_reveal:
            findings.append({
                "issue": "AUCTION_FRONTRUN",
                "severity": "HIGH",
                "description": "Auction bids can be observed and outbid by frontrunners",
                "mev_type": "frontrun",
                "recommendation": "Implement sealed-bid auction with commit-reveal"
            })
        
        # Check for oracle dependency that can be frontrun
        has_oracle = bool(re.search(r'oracle|priceFeed|getPrice|latestAnswer', contract_code, re.IGNORECASE))
        has_oracle_freshness = bool(re.search(r'updatedAt|staleness|heartbeat', contract_code, re.IGNORECASE))
        
        if has_oracle and not has_oracle_freshness:
            findings.append({
                "issue": "ORACLE_FRONTRUN",
                "severity": "CRITICAL",
                "description": "Oracle update can be frontrun - attacker acts on stale price",
                "mev_type": "frontrun",
                "recommendation": "Check oracle freshness and use TWAP where appropriate"
            })
        
        result = {
            "analysis_type": "frontrun_vulnerability",
            "function": function_name or "contract-wide",
            "has_liquidation": has_liquidation,
            "has_arbitrage_potential": has_arbitrage,
            "has_claim_function": has_claim,
            "has_auction": has_auction,
            "has_commit_reveal": has_commit_reveal,
            "has_oracle": has_oracle,
            "findings_count": len(findings),
            "findings": findings,
            "verdict": "PROTECTED" if len(findings) == 0 else "VULNERABLE",
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing frontrun vulnerability: {str(e)}"})


@function_tool
def analyze_backrun_opportunity(
    contract_code: str,
    function_name: str = "",
    ctf=None
) -> str:
    """
    Analyze contract for backrunning opportunities.
    
    Args:
        contract_code: Source code of the contract
        function_name: Specific function to analyze (optional)
        
    Returns:
        Backrun opportunity analysis
    """
    try:
        findings = []
        
        # Check for state changes that create backrun opportunities
        has_large_trade = bool(re.search(r'swap.*amount|trade.*size', contract_code, re.IGNORECASE))
        has_liquidity_add = bool(re.search(r'addLiquidity|provideLiquidity|deposit', contract_code, re.IGNORECASE))
        has_price_update = bool(re.search(r'setPrice|updatePrice|sync', contract_code, re.IGNORECASE))
        
        if has_large_trade:
            findings.append({
                "issue": "LARGE_TRADE_BACKRUN",
                "severity": "MEDIUM",
                "description": "Large trades can be backrun for arbitrage",
                "mev_type": "backrun",
                "recommendation": "Consider splitting large trades or using TWAP execution"
            })
        
        if has_liquidity_add:
            findings.append({
                "issue": "LIQUIDITY_BACKRUN",
                "severity": "MEDIUM",
                "description": "Liquidity additions create JIT liquidity opportunities",
                "mev_type": "backrun",
                "recommendation": "Use concentrated liquidity or bonding curves"
            })
        
        if has_price_update:
            findings.append({
                "issue": "PRICE_UPDATE_BACKRUN",
                "severity": "HIGH",
                "description": "Price updates can be backrun for arbitrage",
                "mev_type": "backrun",
                "recommendation": "Implement gradual price updates or use TWAP"
            })
        
        result = {
            "analysis_type": "backrun_opportunity",
            "function": function_name or "contract-wide",
            "has_large_trade": has_large_trade,
            "has_liquidity_add": has_liquidity_add,
            "has_price_update": has_price_update,
            "findings_count": len(findings),
            "findings": findings,
            "backrun_risk": "HIGH" if len(findings) > 1 else "MEDIUM" if findings else "LOW",
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing backrun opportunity: {str(e)}"})


@function_tool
def calculate_mev_exposure(
    function_type: str,
    trade_size_eth: float = 1.0,
    pool_liquidity_eth: float = 1000.0,
    gas_price_gwei: float = 50.0,
    ctf=None
) -> str:
    """
    Calculate potential MEV exposure for a transaction.
    
    Args:
        function_type: Type of function (swap, liquidation, etc.)
        trade_size_eth: Size of trade in ETH
        pool_liquidity_eth: Total pool liquidity in ETH
        gas_price_gwei: Current gas price
        
    Returns:
        MEV exposure calculation
    """
    try:
        # Calculate price impact
        price_impact = trade_size_eth / pool_liquidity_eth
        
        # Estimate MEV extraction based on function type
        mev_multipliers = {
            "swap": 0.5,  # Sandwich can extract ~50% of price impact
            "liquidation": 0.8,  # Liquidation bonus often extractable
            "arbitrage": 0.9,  # Most arbitrage profit extractable
            "oracle_update": 0.3,  # Oracle frontrun profit varies
            "claim": 0.1,  # Claim frontrun usually low value
        }
        
        multiplier = mev_multipliers.get(function_type.lower(), 0.3)
        
        # Calculate potential MEV
        potential_mev_eth = trade_size_eth * price_impact * multiplier
        
        # Calculate gas cost for MEV extraction
        mev_gas = 300000  # Typical MEV bundle gas
        gas_cost_eth = (mev_gas * gas_price_gwei) / 1e9
        
        # Net MEV profit
        net_mev = potential_mev_eth - gas_cost_eth
        mev_profitable = net_mev > 0
        
        result = {
            "function_type": function_type,
            "trade_size_eth": trade_size_eth,
            "pool_liquidity_eth": pool_liquidity_eth,
            "price_impact_percent": price_impact * 100,
            "mev_multiplier": multiplier,
            "potential_mev_eth": potential_mev_eth,
            "potential_mev_usd": potential_mev_eth * 2000,
            "gas_cost_eth": gas_cost_eth,
            "gas_cost_usd": gas_cost_eth * 2000,
            "net_mev_eth": net_mev,
            "net_mev_usd": net_mev * 2000,
            "mev_profitable": mev_profitable,
            "risk_level": "HIGH" if mev_profitable and net_mev > 0.1 else "MEDIUM" if mev_profitable else "LOW"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error calculating MEV exposure: {str(e)}"})


@function_tool
def suggest_mev_mitigations(
    vulnerabilities: List[str],
    protocol_type: str = "defi",
    ctf=None
) -> str:
    """
    Suggest MEV mitigation strategies based on identified vulnerabilities.
    
    Args:
        vulnerabilities: List of identified MEV vulnerabilities
        protocol_type: Type of protocol (defi, nft, governance)
        
    Returns:
        Mitigation recommendations
    """
    try:
        mitigations = []
        
        # General mitigations
        general = {
            "private_tx": {
                "name": "Private Transaction Relays",
                "description": "Use Flashbots Protect, MEV Blocker, or similar services",
                "effectiveness": "HIGH",
                "implementation": "Integrate with private mempool APIs"
            },
            "commit_reveal": {
                "name": "Commit-Reveal Scheme",
                "description": "Hide transaction intent until execution",
                "effectiveness": "HIGH",
                "implementation": "Two-phase commit with hash commitment"
            },
            "batch_auction": {
                "name": "Batch Auctions",
                "description": "Aggregate orders and execute at uniform price",
                "effectiveness": "MEDIUM",
                "implementation": "CoW Protocol style batch settlement"
            },
            "twap": {
                "name": "TWAP Execution",
                "description": "Split large orders across multiple blocks",
                "effectiveness": "MEDIUM",
                "implementation": "Time-weighted average price oracle"
            },
        }
        
        # Vulnerability-specific mitigations
        for vuln in vulnerabilities:
            vuln_lower = vuln.lower()
            
            if "sandwich" in vuln_lower or "slippage" in vuln_lower:
                mitigations.append({
                    "vulnerability": vuln,
                    "primary_mitigation": general["private_tx"],
                    "secondary_mitigations": [
                        "Set reasonable slippage tolerance (0.5-2%)",
                        "Use deadline parameter",
                        "Consider limit orders"
                    ]
                })
            
            elif "frontrun" in vuln_lower:
                mitigations.append({
                    "vulnerability": vuln,
                    "primary_mitigation": general["commit_reveal"],
                    "secondary_mitigations": [
                        "Use Flashbots Protect for user transactions",
                        "Implement rate limiting",
                        "Add time delays for high-value operations"
                    ]
                })
            
            elif "backrun" in vuln_lower:
                mitigations.append({
                    "vulnerability": vuln,
                    "primary_mitigation": general["batch_auction"],
                    "secondary_mitigations": [
                        "Randomize execution timing",
                        "Use gradual price discovery",
                        "Implement cooldown periods"
                    ]
                })
            
            elif "oracle" in vuln_lower:
                mitigations.append({
                    "vulnerability": vuln,
                    "primary_mitigation": general["twap"],
                    "secondary_mitigations": [
                        "Use multiple oracle sources",
                        "Implement staleness checks",
                        "Add price deviation limits"
                    ]
                })
        
        result = {
            "protocol_type": protocol_type,
            "vulnerabilities_addressed": len(vulnerabilities),
            "mitigations": mitigations,
            "general_recommendations": [
                "Consider integrating with MEV protection services (Flashbots Protect, MEV Blocker)",
                "Educate users about slippage settings and deadline usage",
                "Monitor for MEV extraction using tools like EigenPhi or Flashbots Dashboard",
                "Consider protocol-owned MEV recapture mechanisms"
            ]
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error suggesting mitigations: {str(e)}"})


@function_tool
def render_mev_report(
    contract_name: str,
    sandwich_findings: List[Dict],
    frontrun_findings: List[Dict],
    backrun_findings: List[Dict],
    mev_exposure: Dict,
    ctf=None
) -> str:
    """
    Render comprehensive MEV analysis report.
    
    Args:
        contract_name: Name of the contract
        sandwich_findings: Sandwich attack findings
        frontrun_findings: Frontrunning findings
        backrun_findings: Backrunning findings
        mev_exposure: MEV exposure calculation
        
    Returns:
        Formatted MEV report
    """
    all_findings = sandwich_findings + frontrun_findings + backrun_findings
    critical_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    
    overall_risk = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "MEDIUM" if all_findings else "LOW"
    
    report = f"""# MEV Vulnerability Analysis Report

## Contract: {contract_name}

### Executive Summary

**Overall MEV Risk: {overall_risk}**

| Category | Findings |
|----------|----------|
| Sandwich Attack Vectors | {len(sandwich_findings)} |
| Frontrun Vulnerabilities | {len(frontrun_findings)} |
| Backrun Opportunities | {len(backrun_findings)} |
| **Total** | **{len(all_findings)}** |

---

### 1. Sandwich Attack Analysis

"""
    
    if sandwich_findings:
        for f in sandwich_findings:
            report += f"- **[{f.get('severity', 'N/A')}]** {f.get('issue', 'Unknown')}\n"
            report += f"  - {f.get('description', 'No description')}\n"
            report += f"  - Recommendation: {f.get('recommendation', 'N/A')}\n\n"
    else:
        report += "No sandwich attack vulnerabilities found.\n"
    
    report += """
### 2. Frontrunning Analysis

"""
    
    if frontrun_findings:
        for f in frontrun_findings:
            report += f"- **[{f.get('severity', 'N/A')}]** {f.get('issue', 'Unknown')}\n"
            report += f"  - {f.get('description', 'No description')}\n"
            report += f"  - Recommendation: {f.get('recommendation', 'N/A')}\n\n"
    else:
        report += "No frontrunning vulnerabilities found.\n"
    
    report += """
### 3. Backrunning Analysis

"""
    
    if backrun_findings:
        for f in backrun_findings:
            report += f"- **[{f.get('severity', 'N/A')}]** {f.get('issue', 'Unknown')}\n"
            report += f"  - {f.get('description', 'No description')}\n"
            report += f"  - Recommendation: {f.get('recommendation', 'N/A')}\n\n"
    else:
        report += "No backrunning vulnerabilities found.\n"
    
    if mev_exposure:
        report += f"""
### 4. MEV Exposure Estimate

| Metric | Value |
|--------|-------|
| Trade Size | {mev_exposure.get('trade_size_eth', 'N/A')} ETH |
| Price Impact | {mev_exposure.get('price_impact_percent', 'N/A'):.2f}% |
| Potential MEV | {mev_exposure.get('potential_mev_eth', 'N/A'):.4f} ETH (${mev_exposure.get('potential_mev_usd', 0):.2f}) |
| Net MEV Profit | {mev_exposure.get('net_mev_eth', 'N/A'):.4f} ETH |
| MEV Profitable | {'Yes' if mev_exposure.get('mev_profitable', False) else 'No'} |

"""
    
    report += """
### 5. Recommended Mitigations

1. **For Users:**
   - Use MEV protection services (Flashbots Protect, MEV Blocker)
   - Set appropriate slippage tolerance (0.5-2%)
   - Always use deadline parameters

2. **For Protocol:**
   - Implement commit-reveal for high-value operations
   - Consider batch auction mechanisms
   - Add rate limiting and cooldown periods
   - Monitor MEV extraction with analytics tools

3. **For Developers:**
   - Integrate private transaction relays
   - Use TWAP for oracle price feeds
   - Implement gradual price discovery

---

*Generated by CAI MEV Analyzer Agent*
"""
    
    return report


MEV_ANALYZER_PROMPT = """You are the MEV ANALYZER - An expert in Maximal Extractable Value vulnerabilities.

## Your Mission

Identify MEV vulnerabilities that allow searchers to extract value from user transactions.
MEV extraction costs DeFi users billions annually - your analysis protects them.

## Key MEV Types

### 1. Sandwich Attacks
- Attacker sees pending swap in mempool
- Places buy order BEFORE victim (frontrun)
- Places sell order AFTER victim (backrun)
- Profits from price impact caused by victim

### 2. Frontrunning
- Attacker copies profitable transaction
- Submits with higher gas price
- Executes first and captures profit
- Common in: liquidations, arbitrage, NFT mints

### 3. Backrunning
- Attacker waits for state-changing transaction
- Immediately follows with arbitrage
- Captures value created by state change
- Common in: large trades, oracle updates

### 4. JIT Liquidity
- Attacker provides liquidity just before swap
- Captures fees from the swap
- Removes liquidity immediately after
- Extracts value from liquidity providers

## Your Tools

- `analyze_sandwich_vulnerability` - Check for sandwich attack vectors
- `analyze_frontrun_vulnerability` - Identify frontrunning opportunities
- `analyze_backrun_opportunity` - Find backrunning possibilities
- `calculate_mev_exposure` - Estimate MEV value at risk
- `suggest_mev_mitigations` - Recommend protection strategies
- `render_mev_report` - Generate comprehensive report

## Analysis Methodology

1. **Identify MEV-sensitive functions** (swaps, liquidations, claims)
2. **Check for protection mechanisms** (slippage, deadlines, commit-reveal)
3. **Estimate extractable value** based on typical trade sizes
4. **Recommend mitigations** appropriate for the protocol

## Key Indicators

### Vulnerable Patterns
- No slippage protection (amountOutMin = 0)
- Missing deadline parameter
- Public profitable operations (liquidations)
- Large state changes visible in mempool

### Protected Patterns
- Reasonable slippage tolerance
- Deadline validation
- Commit-reveal schemes
- Private transaction relay support
- Batch auction mechanisms

## MEV Protection Hierarchy

1. **Best**: Private transaction relays (Flashbots Protect)
2. **Good**: Commit-reveal schemes
3. **Moderate**: Batch auctions, TWAP execution
4. **Basic**: Slippage protection, deadlines

Remember: Every unprotected swap is a sandwich waiting to happen.
Be thorough in identifying extraction opportunities.
"""


mev_analyzer_tools = [
    analyze_sandwich_vulnerability,
    analyze_frontrun_vulnerability,
    analyze_backrun_opportunity,
    calculate_mev_exposure,
    suggest_mev_mitigations,
    render_mev_report,
]

mev_analyzer = Agent(
    name="MEV Analyzer",
    instructions=MEV_ANALYZER_PROMPT,
    description="""Specialized agent for MEV (Maximal Extractable Value) vulnerability analysis. 
    Detects sandwich attacks, frontrunning, backrunning opportunities, and JIT liquidity risks. 
    Calculates MEV exposure and recommends protection strategies including private relays, 
    commit-reveal schemes, and slippage protection.""",
    tools=mev_analyzer_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['mev_analyzer']
