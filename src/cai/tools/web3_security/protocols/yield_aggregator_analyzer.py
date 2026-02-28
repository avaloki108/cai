"""
Yield Aggregator Analyzer - DeFi Yield Protocol Security Analysis

Analyzes DeFi yield aggregator protocols for security vulnerabilities:
- Harvest vulnerability detection
- TVL manipulation risks
- Strategy security issues
- Compound and reinvestment risks
- Cross-strategy interactions
- Withdrawal pattern vulnerabilities
"""

import os
import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
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


class YieldStrategy(Enum):
    SINGLE = "single"
    COMPOUND = "compound"
    LEVERAGE = "leverage"
    DELTA_NEUTRAL = "delta_neutral"
    BASIS_TRADE = "basis_trade"


@dataclass
class YieldVulnerability:
    """Represents a yield aggregator vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    attack_vector: str
    mitigation: str
    affected_functions: List[str]


@function_tool
def detect_harvest_vulnerabilities(contract_code: str, ctf=None) -> str:
    """
    Detect vulnerabilities in harvest/reward collection mechanisms.
    
    Args:
        contract_code: Source code of the yield aggregator contract
        
    Returns:
        JSON with harvest vulnerability analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for harvest function
        if "harvest" in code_lower or "collect" in code_lower:
            # Check for access control
            if "onlyowner" not in code_lower and "onlystrategist" not in code_lower:
                vulnerabilities.append({
                    "type": "UNPROTECTED_HARVEST",
                    "severity": "HIGH",
                    "description": "Harvest function not access controlled",
                    "attack_vector": "Attacker can trigger harvest at unfavorable times",
                    "mitigation": "Add access control or allowlist for harvesters"
                })
            
            # Check for profit calculation
            if "profit" in code_lower:
                # Check for price manipulation protection
                if "twap" not in code_lower and "oracle" not in code_lower:
                    vulnerabilities.append({
                        "type": "MANIPULABLE_PROFIT_CALCULATION",
                        "severity": "HIGH",
                        "description": "Profit calculation uses spot prices",
                        "attack_vector": "Manipulate prices before harvest",
                        "mitigation": "Use TWAP or oracle for profit calculation"
                    })
            
            # Check for harvest cooldown
            if "harvestcooldown" not in code_lower:
                vulnerabilities.append({
                    "type": "NO_HARVEST_COOLDOWN",
                    "severity": "MEDIUM",
                    "description": "No cooldown between harvests",
                    "attack_vector": "Force frequent harvests for MEV",
                    "mitigation": "Add harvest cooldown period"
                })
            
            # Check for harvest fee
            if "harvestfee" in code_lower:
                # Check for fee manipulation
                if "setharvestfee" in code_lower:
                    if "onlyowner" not in code_lower:
                        vulnerabilities.append({
                            "type": "MANIPULABLE_HARVEST_FEE",
                            "severity": "MEDIUM",
                            "description": "Harvest fee can be changed",
                            "attack_vector": "Set fee to 100% before harvest",
                            "mitigation": "Add governance controls or fee cap"
                        })
        
        # Check for reward selling
        if "sellreward" in code_lower or "swapreward" in code_lower:
            # Check for slippage protection
            if "minamountout" not in code_lower:
                vulnerabilities.append({
                    "type": "REWARD_SALE_MANIPULATION",
                    "severity": "HIGH",
                    "description": "Reward sale without slippage protection",
                    "attack_vector": "Sandwich reward sale transaction",
                    "mitigation": "Add slippage protection to reward swap"
                })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "harvest_vulnerabilities"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting harvest vulnerabilities: {str(e)}"})


@function_tool
def detect_tvl_manipulation(contract_code: str, ctf=None) -> str:
    """
    Detect TVL manipulation vulnerabilities.
    
    Args:
        contract_code: Source code of the vault contract
        
    Returns:
        JSON with TVL manipulation analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for TVL calculation
        if "tvl" in code_lower or "totalassets" in code_lower:
            # Check for share price calculation
            if "shareprice" in code_lower or "pricepershare" in code_lower:
                # Check for first deposit attack
                if "firstdeposit" not in code_lower:
                    vulnerabilities.append({
                        "type": "FIRST_DEPOSIT_ATTACK",
                        "severity": "HIGH",
                        "description": "No first deposit protection",
                        "attack_vector": "Donate to vault, inflate share price",
                        "mitigation": "Add minimum deposit or dead shares"
                    })
                
                # Check for donation attack
                if "donation" not in code_lower and "sweep" not in code_lower:
                    vulnerabilities.append({
                        "type": "DONATION_ATTACK",
                        "severity": "MEDIUM",
                        "description": "Asset donation can manipulate share price",
                        "attack_vector": "Donate tokens to inflate TVL artificially",
                        "mitigation": "Implement sweep function for unexpected tokens"
                    })
            
            # Check for TVL oracle dependency
            if "oracle" in code_lower:
                vulnerabilities.append({
                    "type": "ORACLE_DEPENDENCY_TVL",
                    "severity": "MEDIUM",
                    "description": "TVL depends on oracle prices",
                    "attack_vector": "Oracle manipulation affects TVL",
                    "mitigation": "Use TWAP or multiple oracles"
                })
        
        # Check for deposit/withdrawal limits
        if "depositlimit" in code_lower:
            vulnerabilities.append({
                "type": "DEPOSIT_LIMIT",
                "severity": "INFO",
                "description": "Deposit limit exists",
                "attack_vector": "May prevent TVL manipulation",
                "mitigation": "Good practice - monitor for changes"
            })
        else:
            vulnerabilities.append({
                "type": "NO_DEPOSIT_LIMIT",
                "severity": "LOW",
                "description": "No deposit limit",
                "attack_vector": "Large deposits can affect strategy execution",
                "mitigation": "Consider adding deposit limits"
            })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "tvl_manipulation"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting TVL manipulation: {str(e)}"})


@function_tool
def detect_strategy_risks(contract_code: str, ctf=None) -> str:
    """
    Detect risks in strategy implementation.
    
    Args:
        contract_code: Source code of the strategy contract
        
    Returns:
        JSON with strategy risk analysis
    """
    try:
        risks = []
        code_lower = contract_code.lower()
        
        # Check for strategy pattern
        if "strategy" in code_lower or "invest" in code_lower:
            # Check for withdrawal path
            if "withdraw" in code_lower:
                # Check for emergency exit
                if "emergencyexit" not in code_lower and "pause" not in code_lower:
                    risks.append({
                        "type": "NO_EMGENCY_EXIT",
                        "severity": "HIGH",
                        "description": "No emergency exit mechanism",
                        "attack_vector": "Cannot quickly exit compromised strategy",
                        "mitigation": "Add emergency withdrawal function"
                    })
                
                # Check for withdrawal fee
                if "withdrawalfee" in code_lower:
                    fee_match = re.search(r"withdrawalfee.*?(d+)", code_lower)
                    if fee_match:
                        fee = int(fee_match.group(1))
                        if fee > 100:  # More than 1%
                            risks.append({
                                "type": "HIGH_WITHDRAWAL_FEE",
                                "severity": "MEDIUM",
                                "description": f"Withdrawal fee of {fee} basis points",
                                "attack_vector": "High fees trap user funds",
                                "mitigation": "Reduce withdrawal fee"
                            })
            
            # Check for leverage
            if "leverage" in code_lower or "borrow" in code_lower:
                risks.append({
                    "type": "LEVERAGE_STRATEGY",
                    "severity": "MEDIUM",
                    "description": "Strategy uses leverage",
                    "attack_vector": "Liquidation risk, cascade failures",
                    "mitigation": "Add leverage limits and monitoring"
                })
            
            # Check for external protocol dependency
            external_protocols = ["aave", "compound", "lido", "rocket", "convex", "curve"]
            for protocol in external_protocols:
                if protocol in code_lower:
                    risks.append({
                        "type": "EXTERNAL_PROTOCOL_DEPENDENCY",
                        "severity": "LOW",
                        "description": f"Depends on {protocol}",
                        "attack_vector": f"Vulnerability in {protocol} affects strategy",
                        "mitigation": "Monitor external protocol health"
                    })
            
            # Check for keeper/bot dependency
            if "keeper" in code_lower or "bot" in code_lower:
                if "keeperincentive" in code_lower:
                    risks.append({
                        "type": "KEEPER_DEPENDENCY",
                        "severity": "LOW",
                        "description": "Strategy depends on keepers",
                        "attack_vector": "Keeper not calling rebalance/harvest",
                        "mitigation": "Ensure sufficient keeper incentives"
                    })
        
        return json.dumps({
            "risk_count": len(risks),
            "risks": risks,
            "analysis_type": "strategy_risks"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting strategy risks: {str(e)}"})


@function_tool
def detect_compound_vulnerabilities(contract_code: str, ctf=None) -> str:
    """
    Detect vulnerabilities in compound/reinvestment mechanisms.
    
    Args:
        contract_code: Source code of the compound contract
        
    Returns:
        JSON with compound vulnerability analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for compound mechanism
        if "compound" in code_lower or "reinvest" in code_lower:
            # Check for compound timing
            if "compoundcooldown" not in code_lower:
                vulnerabilities.append({
                    "type": "NO_COMPOUND_COOLDOWN",
                    "severity": "MEDIUM",
                    "description": "No cooldown between compounds",
                    "attack_vector": "Force frequent compounds for MEV",
                    "mitigation": "Add compound cooldown"
                })
            
            # Check for compound access
            if "compound" in code_lower:
                if "onlyowner" not in code_lower:
                    vulnerabilities.append({
                        "type": "PUBLIC_COMPOUND",
                        "severity": "MEDIUM",
                        "description": "Compound function is public",
                        "attack_vector": "Compound at unfavorable times",
                        "mitigation": "Add access control or incentive structure"
                    })
            
            # Check for reward reinvestment
            if "reinvest" in code_lower:
                # Check for slippage on reinvestment
                if "minamount" not in code_lower:
                    vulnerabilities.append({
                        "type": "REINVEST_MANIPULATION",
                        "severity": "HIGH",
                        "description": "Reinvestment without slippage protection",
                        "attack_vector": "Sandwich reinvestment swap",
                        "mitigation": "Add slippage protection"
                    })
        
        # Check for auto-compound
        if "autocompound" in code_lower:
            vulnerabilities.append({
                "type": "AUTO_COMPOUND",
                "severity": "INFO",
                "description": "Auto-compound mechanism detected",
                "attack_vector": "May compound at bad times automatically",
                "mitigation": "Add time-weighted price checks"
            })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "compound_vulnerabilities"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting compound vulnerabilities: {str(e)}"})


@function_tool
def detect_cross_strategy_risks(contract_code: str, ctf=None) -> str:
    """
    Detect risks from interactions between multiple strategies.
    
    Args:
        contract_code: Source code of the vault/strategy contracts
        
    Returns:
        JSON with cross-strategy risk analysis
    """
    try:
        risks = []
        code_lower = contract_code.lower()
        
        # Check for multiple strategies
        if "strategy" in code_lower:
            # Check for strategy switching
            if "setstrategy" in code_lower or "migrate" in code_lower:
                if "timelock" not in code_lower:
                    risks.append({
                        "type": "INSTANT_STRATEGY_SWITCH",
                        "severity": "HIGH",
                        "description": "Strategy can be changed instantly",
                        "attack_vector": "Switch to malicious strategy",
                        "mitigation": "Add timelock for strategy changes"
                    })
            
            # Check for fund migration
            if "migrate" in code_lower:
                risks.append({
                    "type": "MIGRATION_RISK",
                    "severity": "MEDIUM",
                    "description": "Strategy migration detected",
                    "attack_vector": "Funds at risk during migration",
                    "mitigation": "Add emergency pause during migration"
                })
        
        # Check for debt allocation
        if "debt" in code_lower and "allocate" in code_lower:
            risks.append({
                "type": "DEBT_ALLOCATION",
                "severity": "INFO",
                "description": "Debt allocation between strategies",
                "attack_vector": "Uneven allocation affects returns",
                "mitigation": "Implement fair allocation mechanism"
            })
        
        # Check for profit sharing
        if "profitshare" in code_lower or "split" in code_lower:
            risks.append({
                "type": "PROFIT_SHARING",
                "severity": "INFO",
                "description": "Profit sharing between strategies",
                "attack_vector": "May create cross-strategy dependencies",
                "mitigation": "Ensure fair and transparent sharing"
            })
        
        return json.dumps({
            "risk_count": len(risks),
            "risks": risks,
            "analysis_type": "cross_strategy_risks"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting cross-strategy risks: {str(e)}"})


@function_tool
def analyze_withdraw_patterns(contract_code: str, ctf=None) -> str:
    """
    Analyze withdrawal patterns for security issues.
    
    Args:
        contract_code: Source code of the vault contract
        
    Returns:
        JSON with withdrawal pattern analysis
    """
    try:
        issues = []
        code_lower = contract_code.lower()
        
        # Check for withdrawal mechanism
        if "withdraw" in code_lower:
            # Check for withdrawal queue
            if "withdrawalqueue" in code_lower:
                issues.append({
                    "type": "WITHDRAWAL_QUEUE",
                    "severity": "INFO",
                    "description": "Withdrawal queue system detected",
                    "attack_vector": "Queue may be gamed",
                    "mitigation": "Implement fair queue ordering"
                })
            
            # Check for instant withdrawal
            if "instantwithdraw" in code_lower:
                issues.append({
                    "type": "INSTANT_WITHDRAWAL",
                    "severity": "INFO",
                    "description": "Instant withdrawal available",
                    "attack_vector": "May drain liquidity quickly",
                    "mitigation": "Add withdrawal limits"
                })
            
            # Check for withdrawal delay
            if "withdrawaldelay" not in code_lower and "lock" not in code_lower:
                issues.append({
                    "type": "NO_WITHDRAWAL_DELAY",
                    "severity": "LOW",
                    "description": "No withdrawal delay",
                    "attack_vector": "Bank run scenario",
                    "mitigation": "Consider adding withdrawal delay"
                })
            
            # Check for max withdrawal
            if "maxwithdraw" in code_lower:
                issues.append({
                    "type": "WITHDRAWAL_LIMIT",
                    "severity": "INFO",
                    "description": "Withdrawal limit exists",
                    "attack_vector": "May prevent large withdrawals",
                    "mitigation": "Good practice for TVL stability"
                })
            
            # Check for PnG (Pool and Game) patterns
            if "pendingwithdrawal" in code_lower:
                issues.append({
                    "type": "PENDING_WITHDRAWAL",
                    "severity": "MEDIUM",
                    "description": "Pending withdrawal system",
                    "attack_vector": "Funds locked during pending period",
                    "mitigation": "Add cancellation or timeout mechanism"
                })
        
        # Check for reentrancy in withdrawal
        if "withdraw" in code_lower:
            if "nonreentrant" not in code_lower:
                issues.append({
                    "type": "WITHDRAWAL_REENTRANCY",
                    "severity": "HIGH",
                    "description": "Withdrawal without reentrancy protection",
                    "attack_vector": "Reentrancy during withdrawal",
                    "mitigation": "Add ReentrancyGuard"
                })
        
        return json.dumps({
            "issue_count": len(issues),
            "issues": issues,
            "analysis_type": "withdraw_patterns"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing withdrawal patterns: {str(e)}"})


# Create the agent
yield_aggregator_analyzer_agent = Agent(
    name="Yield Aggregator Analyzer",
    instructions="""You are an expert in DeFi yield aggregator security. Your role is to:

1. **Analyze Harvest Functions**: Check reward collection and selling mechanisms
2. **Detect TVL Manipulation**: Find first deposit and donation attack vectors
3. **Assess Strategy Risks**: Evaluate leverage, external dependencies, and emergency exits
4. **Check Compound Logic**: Validate reinvestment mechanisms
5. **Analyze Cross-Strategy Risks**: Find strategy migration and allocation issues
6. **Review Withdrawal Patterns**: Check for bank run risks and reentrancy

Key attack vectors:
- First deposit attack (inflating share price)
- Harvest manipulation (sandwich reward sales)
- Strategy migration attacks
- Withdrawal reentrancy
- Donation attacks on vaults

Provide severity ratings (CRITICAL, HIGH, MEDIUM, LOW, INFO) and specific mitigations.""",
    tools=[
        detect_harvest_vulnerabilities,
        detect_tvl_manipulation,
        detect_strategy_risks,
        detect_compound_vulnerabilities,
        detect_cross_strategy_risks,
        analyze_withdraw_patterns
    ],
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_MODEL", "alias1"),
        openai_client=AsyncOpenAI(
            base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            api_key=api_key
        )
    )
)

# Export for registration
yield_aggregator_analyzer = yield_aggregator_analyzer_agent
