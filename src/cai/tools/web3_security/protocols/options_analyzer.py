"""
Options Protocol Analyzer - DeFi Options Security Analysis

Analyzes DeFi options protocols for security vulnerabilities including:
- Option mechanics (call/put, expiry, exercise)
- Greeks manipulation (delta, gamma, vega, theta)
- Settlement security
- Liquidation mechanics
- Premium calculation issues
- Oracle dependency risks
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


class OptionType(Enum):
    CALL = "call"
    PUT = "put"
    STRADDLE = "straddle"
    STRANGLE = "strangle"
    SPREAD = "spread"


class ExerciseStyle(Enum):
    EUROPEAN = "european"
    AMERICAN = "american"
    BERMUDAN = "bermudan"


@dataclass
class OptionsVulnerability:
    """Represents an options protocol vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    attack_vector: str
    mitigation: str
    affected_functions: List[str]


@function_tool
def analyze_option_mechanics(contract_code: str, ctf=None) -> str:
    """
    Analyze option contract mechanics for security issues.
    
    Args:
        contract_code: Source code of the options contract
        
    Returns:
        JSON with option mechanics analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Detect option type
        option_types_detected = []
        if "call" in code_lower and "strike" in code_lower:
            option_types_detected.append("call")
        if "put" in code_lower and "strike" in code_lower:
            option_types_detected.append("put")
        
        # Check for expiry handling
        if "expiry" in code_lower or "expiration" in code_lower:
            # Check for expiry manipulation
            if "setexpiry" in code_lower:
                if "onlyowner" not in code_lower:
                    vulnerabilities.append({
                        "type": "MANIPULABLE_EXPIRY",
                        "severity": "HIGH",
                        "description": "Option expiry can be modified",
                        "attack_vector": "Change expiry to manipulate option value",
                        "mitigation": "Make expiry immutable or require governance"
                    })
            
            # Check for timezone handling
            if "block.timestamp" in code_lower:
                vulnerabilities.append({
                    "type": "BLOCK_TIMESTAMP_DEPENDENCY",
                    "severity": "LOW",
                    "description": "Using block.timestamp for expiry",
                    "attack_vector": "Miners can slightly manipulate timestamp",
                    "mitigation": "Use block.number or accept timestamp limitations"
                })
        else:
            vulnerabilities.append({
                "type": "NO_EXPIRY_MECHANISM",
                "severity": "MEDIUM",
                "description": "No clear expiry mechanism detected",
                "attack_vector": "Options may never expire",
                "mitigation": "Implement clear expiry logic"
            })
        
        # Check for exercise mechanism
        if "exercise" in code_lower:
            # Check for exercise validation
            if "canexercise" not in code_lower and "isexerciseable" not in code_lower:
                vulnerabilities.append({
                    "type": "UNVALIDATED_EXERCISE",
                    "severity": "HIGH",
                    "description": "No validation before exercise",
                    "attack_vector": "Exercise in invalid conditions",
                    "mitigation": "Add validation for exercise conditions"
                })
            
            # Check for early exercise (American vs European)
            if "earlyexercise" in code_lower or "american" in code_lower:
                vulnerabilities.append({
                    "type": "AMERICAN_STYLE_OPTIONS",
                    "severity": "INFO",
                    "description": "American-style early exercise detected",
                    "attack_vector": "Early exercise can be used for MEV",
                    "mitigation": "Consider European-style or add exercise fees"
                })
        else:
            vulnerabilities.append({
                "type": "NO_EXERCISE_MECHANISM",
                "severity": "HIGH",
                "description": "No exercise mechanism found",
                "attack_vector": "Cannot exercise options",
                "mitigation": "Implement exercise function"
            })
        
        # Check for strike price handling
        if "strike" in code_lower:
            if "updatestrike" in code_lower or "setstrike" in code_lower:
                vulnerabilities.append({
                    "type": "UPDATABLE_STRIKE",
                    "severity": "HIGH",
                    "description": "Strike price can be updated",
                    "attack_vector": "Manipulate strike for profit",
                    "mitigation": "Make strike immutable or add strict controls"
                })
        
        return json.dumps({
            "option_types_detected": option_types_detected,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "option_mechanics"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing option mechanics: {str(e)}"})


@function_tool
def analyze_greeks_manipulation(contract_code: str, ctf=None) -> str:
    """
    Analyze exposure to Greeks manipulation attacks.
    
    Args:
        contract_code: Source code of the options protocol
        
    Returns:
        JSON with Greeks manipulation analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for delta exposure
        if "delta" in code_lower or "hedge" in code_lower:
            # Check for delta hedging
            if "rebalance" in code_lower:
                if "maxrebalance" not in code_lower and "rebalancecooldown" not in code_lower:
                    vulnerabilities.append({
                        "type": "UNLIMITED_REBALANCING",
                        "severity": "MEDIUM",
                        "description": "Unlimited delta rebalancing",
                        "attack_vector": "Force frequent rebalancing for MEV extraction",
                        "mitigation": "Add rate limiting to rebalancing"
                    })
        
        # Check for gamma exposure (rate of delta change)
        if "gamma" in code_lower:
            vulnerabilities.append({
                "type": "GAMMA_EXPOSURE",
                "severity": "INFO",
                "description": "Gamma exposure detected in calculations",
                "attack_vector": "Large price moves cause hedging losses",
                "mitigation": "Monitor gamma exposure and set limits"
            })
        
        # Check for vega exposure (volatility sensitivity)
        if "volatility" in code_lower or "iv" in code_lower:
            if "impliedvolatility" in code_lower:
                # Check for IV manipulation
                if "oracle" not in code_lower:
                    vulnerabilities.append({
                        "type": "MANIPULABLE_VOLATILITY",
                        "severity": "HIGH",
                        "description": "Implied volatility without oracle",
                        "attack_vector": "Manipulate IV for pricing advantage",
                        "mitigation": "Use on-chain volatility oracle or TWAP"
                    })
        
        # Check for theta decay (time decay)
        if "theta" in code_lower or "timedecay" in code_lower:
            vulnerabilities.append({
                "type": "THETA_DECAY_HANDLING",
                "severity": "INFO",
                "description": "Theta decay in calculations",
                "attack_vector": "Rapid time decay near expiry",
                "mitigation": "Ensure fair decay calculation"
            })
        
        # Check for portfolio Greeks aggregation
        if "portfoliodelta" in code_lower or "totaldelta" in code_lower:
            if "maxdelta" not in code_lower and "deltalimit" not in code_lower:
                vulnerabilities.append({
                    "type": "UNLIMITED_PORTFOLIO_DELTA",
                    "severity": "MEDIUM",
                    "description": "No delta limits on portfolio",
                    "attack_vector": "Excessive directional exposure",
                    "mitigation": "Add portfolio delta limits"
                })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "greeks_manipulation"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing Greeks manipulation: {str(e)}"})


@function_tool
def analyze_settlement_security(contract_code: str, ctf=None) -> str:
    """
    Analyze option settlement and payout security.
    
    Args:
        contract_code: Source code of the options contract
        
    Returns:
        JSON with settlement security analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for settlement mechanism
        if "settle" in code_lower or "payout" in code_lower or "claim" in code_lower:
            # Check for settlement price source
            if "oracle" in code_lower:
                # Check for oracle manipulation protection
                if "twap" not in code_lower:
                    vulnerabilities.append({
                        "type": "SPOT_PRICE_SETTLEMENT",
                        "severity": "HIGH",
                        "description": "Settlement uses spot price from oracle",
                        "attack_vector": "Flash loan price manipulation at settlement",
                        "mitigation": "Use TWAP or multiple oracle sources"
                    })
            else:
                vulnerabilities.append({
                    "type": "NO_PRICE_SOURCE",
                    "severity": "CRITICAL",
                    "description": "No oracle for settlement price",
                    "attack_vector": "Settlement price can be manipulated",
                    "mitigation": "Integrate reliable oracle"
                })
            
            # Check for settlement window
            if "settlementwindow" in code_lower:
                window_match = re.search(r"settlementwindow.*?(d+)", code_lower)
                if window_match:
                    window = int(window_match.group(1))
                    if window < 3600:  # Less than 1 hour
                        vulnerabilities.append({
                            "type": "SHORT_SETTLEMENT_WINDOW",
                            "severity": "MEDIUM",
                            "description": f"Settlement window of {window} seconds",
                            "attack_vector": "Users may miss settlement window",
                            "mitigation": "Extend settlement window"
                        })
            else:
                vulnerabilities.append({
                    "type": "NO_SETTLEMENT_WINDOW",
                    "severity": "LOW",
                    "description": "No settlement window defined",
                    "attack_vector": "Settlement timing uncertainty",
                    "mitigation": "Define clear settlement window"
                })
            
            # Check for collateral handling
            if "collateral" in code_lower:
                if "release" in code_lower or "withdraw" in code_lower:
                    # Check for reentrancy protection
                    if "nonreentrant" not in code_lower and "mutex" not in code_lower:
                        vulnerabilities.append({
                            "type": "SETTLEMENT_REENTRANCY",
                            "severity": "HIGH",
                            "description": "Settlement without reentrancy protection",
                            "attack_vector": "Reentrancy during collateral release",
                            "mitigation": "Add ReentrancyGuard"
                        })
        
        # Check for cash vs physical settlement
        if "physical" in code_lower and "cash" in code_lower:
            vulnerabilities.append({
                "type": "DUAL_SETTLEMENT_MODE",
                "severity": "INFO",
                "description": "Both physical and cash settlement supported",
                "attack_vector": "Settlement mode manipulation",
                "mitigation": "Clear settlement mode selection"
            })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "settlement_security"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing settlement security: {str(e)}"})


@function_tool
def analyze_liquidation_mechanics(contract_code: str, ctf=None) -> str:
    """
    Analyze liquidation mechanics for options positions.
    
    Args:
        contract_code: Source code of the options protocol
        
    Returns:
        JSON with liquidation analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for liquidation mechanism
        if "liquidate" in code_lower:
            # Check for margin system
            if "margin" in code_lower or "collateral" in code_lower:
                # Check for margin ratio calculation
                if "marginratio" in code_lower or "healthfactor" in code_lower:
                    # Check for safe liquidation
                    if "liquidationbonus" in code_lower or "incentive" in code_lower:
                        vulnerabilities.append({
                            "type": "LIQUIDATION_INCENTIVE",
                            "severity": "INFO",
                            "description": "Liquidation incentive exists",
                            "attack_vector": "Liquidators may front-run",
                            "mitigation": "Monitor for front-running patterns"
                        })
                    
                    # Check for partial liquidation
                    if "partial" in code_lower:
                        vulnerabilities.append({
                            "type": "PARTIAL_LIQUIDATION",
                            "severity": "INFO",
                            "description": "Partial liquidation supported",
                            "attack_vector": "Multiple small liquidations",
                            "mitigation": "Add minimum liquidation size"
                        })
                    
                    # Check for liquidation threshold
                    thresh_match = re.search(r"liquidationthreshold.*?(d+)", code_lower)
                    if thresh_match:
                        threshold = int(thresh_match.group(1))
                        if threshold > 90:  # High threshold
                            vulnerabilities.append({
                                "type": "HIGH_LIQUIDATION_THRESHOLD",
                                "severity": "MEDIUM",
                                "description": f"Liquidation threshold of {threshold}%",
                                "attack_vector": "Little time to react before liquidation",
                                "mitigation": "Lower threshold for safety buffer"
                            })
                else:
                    vulnerabilities.append({
                        "type": "NO_MARGIN_TRACKING",
                        "severity": "HIGH",
                        "description": "No margin ratio tracking",
                        "attack_vector": "Cannot determine when to liquidate",
                        "mitigation": "Implement margin ratio calculation"
                    })
            
            # Check for liquidation timing
            if "instantliquidate" in code_lower:
                vulnerabilities.append({
                    "type": "INSTANT_LIQUIDATION",
                    "severity": "MEDIUM",
                    "description": "Instant liquidation possible",
                    "attack_vector": "No grace period for margin calls",
                    "mitigation": "Add grace period or warning system"
                })
        
        # Check for portfolio margin
        if "portfoliomargin" in code_lower:
            vulnerabilities.append({
                "type": "PORTFOLIO_MARGIN",
                "severity": "INFO",
                "description": "Portfolio margin system detected",
                "attack_vector": "Cross-position risk",
                "mitigation": "Monitor correlated positions"
            })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "liquidation_mechanics"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing liquidation mechanics: {str(e)}"})


@function_tool
def analyze_premium_calculation(contract_code: str, ctf=None) -> str:
    """
    Analyze option premium calculation for fairness and manipulation.
    
    Args:
        contract_code: Source code of the options protocol
        
    Returns:
        JSON with premium calculation analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for premium mechanism
        if "premium" in code_lower or "price" in code_lower:
            # Check for pricing model
            pricing_models = []
            if "bsm" in code_lower or "black" in code_lower:
                pricing_models.append("Black-Scholes-Merton")
            if "binomial" in code_lower:
                pricing_models.append("Binomial")
            if "montecarlo" in code_lower:
                pricing_models.append("Monte Carlo")
            
            # Check for on-chain pricing
            if "calculatepremium" in code_lower or "getprice" in code_lower:
                vulnerabilities.append({
                    "type": "ON_CHAIN_PRICING",
                    "severity": "INFO",
                    "description": "Premium calculated on-chain",
                    "attack_vector": "Computation limits may affect accuracy",
                    "mitigation": "Use off-chain pricing with on-chain verification"
                })
            
            # Check for pricing manipulation
            if "volatility" in code_lower:
                if "oracle" not in code_lower and "twap" not in code_lower:
                    vulnerabilities.append({
                        "type": "MANIPULABLE_VOLATILITY_INPUT",
                        "severity": "HIGH",
                        "description": "Volatility input without oracle",
                        "attack_vector": "Manipulate volatility to misprice options",
                        "mitigation": "Use volatility oracle or TWAP"
                    })
            
            # Check for fee handling
            if "fee" in code_lower:
                if "feerate" in code_lower:
                    # Check for fee manipulation
                    if "setfee" in code_lower:
                        if "onlyowner" not in code_lower:
                            vulnerabilities.append({
                                "type": "MANIPULABLE_FEE",
                                "severity": "MEDIUM",
                                "description": "Fee rate can be changed",
                                "attack_vector": "Change fees for profit",
                                "mitigation": "Add governance or fee cap"
                            })
        
        # Check for discount/premium mechanisms
        if "discount" in code_lower:
            vulnerabilities.append({
                "type": "DISCOUNT_MECHANISM",
                "severity": "INFO",
                "description": "Discount mechanism detected",
                "attack_vector": "Discount abuse for profit",
                "mitigation": "Add discount limits and eligibility checks"
            })
        
        return json.dumps({
            "pricing_models_detected": pricing_models if 'pricing_models' in dir() else [],
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "premium_calculation"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing premium calculation: {str(e)}"})


@function_tool
def analyze_oracle_dependency(contract_code: str, ctf=None) -> str:
    """
    Analyze oracle dependency and risk for options pricing.
    
    Args:
        contract_code: Source code of the options protocol
        
    Returns:
        JSON with oracle dependency analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for oracle usage
        oracle_types = []
        if "chainlink" in code_lower:
            oracle_types.append("Chainlink")
        if "uniswap" in code_lower and "twap" in code_lower:
            oracle_types.append("Uniswap TWAP")
        if "tellor" in code_lower:
            oracle_types.append("Tellor")
        if "umbrella" in code_lower:
            oracle_types.append("Umbrella")
        
        if oracle_types:
            # Check for oracle staleness
            if "stale" in code_lower or "updatedAt" in code_lower:
                vulnerabilities.append({
                    "type": "ORACLE_STALENESS_CHECK",
                    "severity": "INFO",
                    "description": "Oracle staleness check exists",
                    "attack_vector": "Stale price usage prevented",
                    "mitigation": "Already implemented - good practice"
                })
            else:
                vulnerabilities.append({
                    "type": "NO_STALENESS_CHECK",
                    "severity": "MEDIUM",
                    "description": "No oracle staleness check",
                    "attack_vector": "Using stale prices for settlement",
                    "mitigation": "Add staleness threshold check"
                })
            
            # Check for multiple oracles
            if len(oracle_types) == 1:
                vulnerabilities.append({
                    "type": "SINGLE_ORACLE_DEPENDENCY",
                    "severity": "MEDIUM",
                    "description": f"Single oracle: {oracle_types[0]}",
                    "attack_vector": "Oracle failure or manipulation",
                    "mitigation": "Add backup oracle sources"
                })
            else:
                vulnerabilities.append({
                    "type": "MULTI_ORACLE_SYSTEM",
                    "severity": "INFO",
                    "description": f"Multiple oracles: {', '.join(oracle_types)}",
                    "attack_vector": "Median aggregation may have edge cases",
                    "mitigation": "Ensure robust aggregation logic"
                })
        else:
            vulnerabilities.append({
                "type": "NO_ORACLE",
                "severity": "CRITICAL",
                "description": "No oracle dependency detected",
                "attack_vector": "Prices can be manipulated",
                "mitigation": "Integrate reliable oracle"
            })
        
        return json.dumps({
            "oracle_types_detected": oracle_types,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "oracle_dependency"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing oracle dependency: {str(e)}"})


# Create the agent
options_analyzer_agent = Agent(
    name="Options Protocol Analyzer",
    instructions="""You are an expert in DeFi options protocol security. Your role is to:

1. **Analyze Option Mechanics**: Review expiry, exercise, strike handling
2. **Check Greeks Exposure**: Identify delta, gamma, vega, theta manipulation risks
3. **Review Settlement Security**: Validate settlement pricing and collateral handling
4. **Assess Liquidation Mechanics**: Check margin systems and liquidation logic
5. **Validate Premium Calculation**: Ensure fair and manipulation-resistant pricing
6. **Evaluate Oracle Dependencies**: Check oracle security and redundancy

Key attack vectors:
- Greeks manipulation for pricing advantage
- Oracle manipulation at settlement
- Liquidation front-running
- Premium calculation gaming
- Volatility manipulation

Provide severity ratings (CRITICAL, HIGH, MEDIUM, LOW, INFO) and specific mitigations.""",
    tools=[
        analyze_option_mechanics,
        analyze_greeks_manipulation,
        analyze_settlement_security,
        analyze_liquidation_mechanics,
        analyze_premium_calculation,
        analyze_oracle_dependency
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
options_analyzer = options_analyzer_agent
