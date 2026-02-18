"""
MEV Simulator - Maximal Extractable Value Detection and Simulation

Analyzes smart contracts for MEV extraction opportunities and vulnerabilities:
- Sandwich attack detection and simulation
- Frontrunning vulnerability detection
- Backrunning opportunity identification
- JIT liquidity manipulation risks
- MEV exposure calculation
- Mitigation recommendations
"""

import os
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from dotenv import load_dotenv

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool

load_dotenv()

api_key = (
    os.getenv("OPENAI_API_KEY")
    or os.getenv("ANTHROPIC_API_KEY")
    or os.getenv("ALIAS_API_KEY")
    or "sk-placeholder"
)


class MEVType(Enum):
    SANDWICH = "sandwich"
    FRONTRUN = "frontrun"
    BACKRUN = "backrun"
    JIT_LIQUIDITY = "jit_liquidity"
    LIQUIDATION = "liquidation"
    ARBITRAGE = "arbitrage"


@dataclass
class MEVOpportunity:
    """Represents an MEV extraction opportunity"""
    mev_type: MEVType
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    target_functions: List[str]
    estimated_value: str
    attack_steps: List[str]
    mitigation: str


@function_tool
def detect_sandwich_vulnerability(contract_code: str, ctf=None) -> str:
    """
    Detect functions vulnerable to sandwich attacks.
    
    Args:
        contract_code: Source code of the contract
        
    Returns:
        JSON with sandwich vulnerability analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for DEX-like functions
        amm_patterns = [
            ("swap", "Token swap function"),
            ("swapexacttokens", "Exact token swap"),
            ("swapexacteth", "Exact ETH swap"),
            ("addliquidity", "Liquidity addition"),
            ("removeliquidity", "Liquidity removal")
        ]
        
        for pattern, desc in amm_patterns:
            if pattern in code_lower:
                # Check for slippage protection
                if "minamountout" in code_lower or "amountoutmin" in code_lower:
                    # Check if slippage is enforced
                    vulnerabilities.append({
                        "type": "AMM_FUNCTION_WITH_SLIPPAGE",
                        "severity": "MEDIUM",
                        "description": f"{desc} with slippage protection",
                        "attack_vector": "Sandwich if slippage is too high",
                        "target_function": pattern,
                        "mitigation": "Use tight slippage, private mempool"
                    })
                else:
                    vulnerabilities.append({
                        "type": "AMM_FUNCTION_NO_SLIPPAGE",
                        "severity": "HIGH",
                        "description": f"{desc} without slippage protection",
                        "attack_vector": "Classic sandwich attack",
                        "target_function": pattern,
                        "mitigation": "Add minAmountOut parameter"
                    })
        
        # Check for oracle-dependent swaps
        if "swap" in code_lower and "oracle" in code_lower:
            if "twap" not in code_lower:
                vulnerabilities.append({
                    "type": "ORACLE_BASED_SWAP",
                    "severity": "HIGH",
                    "description": "Swap uses spot oracle price",
                    "attack_vector": "Manipulate oracle, then sandwich",
                    "target_function": "swap",
                    "mitigation": "Use TWAP oracle, private mempool"
                })
        
        # Check for large transaction patterns
        if "amount" in code_lower:
            if "maxamount" not in code_lower and "limit" not in code_lower:
                vulnerabilities.append({
                    "type": "NO_TRANSACTION_LIMIT",
                    "severity": "LOW",
                    "description": "No maximum transaction size",
                    "attack_vector": "Large sandwiches more profitable",
                    "target_function": "multiple",
                    "mitigation": "Add transaction size limits"
                })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "sandwich_detection"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting sandwich vulnerabilities: {str(e)}"})


@function_tool
def detect_frontrun_vulnerability(contract_code: str, ctf=None) -> str:
    """
    Detect functions vulnerable to frontrunning.
    
    Args:
        contract_code: Source code of the contract
        
    Returns:
        JSON with frontrunning vulnerability analysis
    """
    try:
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for frontrun-sensitive patterns
        sensitive_patterns = [
            ("bid", "Auction bid"),
            ("offer", "NFT offer"),
            ("buy", "Purchase function"),
            ("claim", "Claim function"),
            ("mint", "Mint function"),
            ("submit", "Submission function"),
            ("commit", "Commit function")
        ]
        
        for pattern, desc in sensitive_patterns:
            if pattern in code_lower:
                # Check for commit-reveal
                if "commit" in code_lower and "reveal" in code_lower:
                    vulnerabilities.append({
                        "type": "COMMIT_REVEAL_PATTERN",
                        "severity": "LOW",
                        "description": f"{desc} uses commit-reveal",
                        "attack_vector": "Commit can still be frontrun",
                        "target_function": pattern,
                        "mitigation": "Use submarine sends or flashbots"
                    })
                else:
                    vulnerabilities.append({
                        "type": "FRONTRUN_VULNERABLE",
                        "severity": "MEDIUM",
                        "description": f"{desc} is frontrunnable",
                        "attack_vector": "Attacker sees transaction and front-runs",
                        "target_function": pattern,
                        "mitigation": "Add commit-reveal or use private mempool"
                    })
        
        # Check for first-come-first-served patterns
        if "first" in code_lower or "queue" in code_lower:
            vulnerabilities.append({
                "type": "FCFS_VULNERABILITY",
                "severity": "HIGH",
                "description": "First-come-first-served pattern",
                "attack_vector": "Priority gas auction (PGA)",
                "target_function": "queue/first",
                "mitigation": "Use fair ordering or randomness"
            })
        
        # Check for NFT mint patterns
        if "mint" in code_lower:
            if "maxsupply" in code_lower or "totalsupply" in code_lower:
                vulnerabilities.append({
                    "type": "LIMITED_MINT_FRONTRUN",
                    "severity": "MEDIUM",
                    "description": "Limited NFT mint",
                    "attack_vector": "Frontrun to get limited NFTs",
                    "target_function": "mint",
                    "mitigation": "Add per-address limits, allowlist"
                })
        
        # Check for auction patterns
        if "auction" in code_lower or "bid" in code_lower:
            if "endtime" in code_lower:
                vulnerabilities.append({
                    "type": "AUCTION_SNIPE_FRONTRUN",
                    "severity": "HIGH",
                    "description": "Timed auction detected",
                    "attack_vector": "Snipe auction at end with frontrun",
                    "target_function": "bid",
                    "mitigation": "Extend auction on late bids"
                })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "frontrun_detection"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting frontrunning: {str(e)}"})


@function_tool
def detect_backrun_opportunity(contract_code: str, ctf=None) -> str:
    """
    Detect state changes that create backrunning opportunities.
    
    Args:
        contract_code: Source code of the contract
        
    Returns:
        JSON with backrunning opportunity analysis
    """
    try:
        opportunities = []
        code_lower = contract_code.lower()
        
        # Check for emit events that trigger backruns
        if "emit" in code_lower:
            event_patterns = [
                ("swap", "Swap event triggers arbitrage"),
                ("liquidation", "Liquidation event for cascading"),
                ("priceupdate", "Price update for oracle refresh"),
                ("rebase", "Rebase event for rebalancing")
            ]
            
            for pattern, desc in event_patterns:
                if pattern in code_lower:
                    opportunities.append({
                        "type": "EVENT_TRIGGERED_BACKRUN",
                        "severity": "INFO",
                        "description": desc,
                        "target_event": pattern,
                        "attack_vector": "Listen for event and backrun",
                        "mitigation": "Use private mempool for sensitive ops"
                    })
        
        # Check for price updates that enable arbitrage
        if "updateprice" in code_lower or "setprice" in code_lower:
            opportunities.append({
                "type": "PRICE_UPDATE_BACKRUN",
                "severity": "MEDIUM",
                "description": "Price update enables arbitrage",
                "target_function": "price update",
                "attack_vector": "Backrun price update for profit",
                "mitigation": "Use TWAP or batch price updates"
            })
        
        # Check for liquidity changes
        if "addliquidity" in code_lower or "removeliquidity" in code_lower:
            opportunities.append({
                "type": "LIQUIDITY_CHANGE_BACKRUN",
                "severity": "MEDIUM",
                "description": "Liquidity changes create arb opportunity",
                "target_function": "liquidity functions",
                "attack_vector": "Backrun liquidity change",
                "mitigation": "Use private mempool"
            })
        
        # Check for rebase mechanics
        if "rebase" in code_lower:
            opportunities.append({
                "type": "REBASE_BACKRUN",
                "severity": "HIGH",
                "description": "Rebase mechanics create MEV",
                "target_function": "rebase",
                "attack_vector": "Trade before/after rebase",
                "mitigation": "Make rebase timing unpredictable"
            })
        
        return json.dumps({
            "opportunity_count": len(opportunities),
            "opportunities": opportunities,
            "analysis_type": "backrun_detection"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting backrunning: {str(e)}"})


@function_tool
def detect_jit_liquidity_risk(contract_code: str, ctf=None) -> str:
    """
    Detect JIT (Just-In-Time) liquidity manipulation risks.
    
    Args:
        contract_code: Source code of the contract
        
    Returns:
        JSON with JIT liquidity risk analysis
    """
    try:
        risks = []
        code_lower = contract_code.lower()
        
        # Check for LP token mechanics
        if "liquiditypool" in code_lower or "addliquidity" in code_lower:
            # Check for lock period
            if "lock" not in code_lower and "cooldown" not in code_lower:
                risks.append({
                    "type": "NO_LP_LOCK",
                    "severity": "HIGH",
                    "description": "No lock period for liquidity",
                    "attack_vector": "Add JIT liquidity, extract fees, remove",
                    "target_function": "add/remove liquidity",
                    "mitigation": "Add minimum lock period for LP tokens"
                })
            
            # Check for fee distribution timing
            if "distribute" in code_lower or "collect" in code_lower:
                risks.append({
                    "type": "INSTANT_FEE_DISTRIBUTION",
                    "severity": "MEDIUM",
                    "description": "Fees distributed immediately",
                    "attack_vector": "Add LP, collect fees, remove LP",
                    "target_function": "fee distribution",
                    "mitigation": "Delay fee distribution"
                })
        
        # Check for concentrated liquidity (Uniswap v3 style)
        if "tick" in code_lower and "range" in code_lower:
            risks.append({
                "type": "CONCENTRATED_LIQUIDITY_JIT",
                "severity": "HIGH",
                "description": "Concentrated liquidity positions",
                "attack_vector": "Place narrow range JIT liquidity",
                "target_function": "mint/burn positions",
                "mitigation": "Add position duration minimum"
            })
        
        # Check for liquidity mining rewards
        if "reward" in code_lower and "stake" in code_lower:
            if "minstakeduration" not in code_lower:
                risks.append({
                    "type": "INSTANT_REWARD_CLAIM",
                    "severity": "MEDIUM",
                    "description": "No minimum stake duration for rewards",
                    "attack_vector": "Stake, claim rewards, unstake immediately",
                    "target_function": "stake/reward",
                    "mitigation": "Add minimum stake duration"
                })
        
        return json.dumps({
            "risk_count": len(risks),
            "risks": risks,
            "analysis_type": "jit_liquidity"
        })
    except Exception as e:
        return json.dumps({"error": f"Error detecting JIT liquidity risks: {str(e)}"})


@function_tool
def simulate_sandwich_attack(
    target_function: str,
    user_amount: float,
    pool_reserve: float,
    pool_reserve_out: float,
    ctf=None
) -> str:
    """
    Simulate a sandwich attack to calculate potential profit.
    
    Args:
        target_function: Function being sandwiched
        user_amount: User's transaction amount
        pool_reserve: Reserve of token being sold
        pool_reserve_out: Reserve of token being bought
        
    Returns:
        JSON with sandwich attack simulation
    """
    try:
        # Simplified constant product AMM simulation
        # actual implementation would use precise math
        
        # Calculate user's output without sandwich
        user_output_no_sandwich = (
            (user_amount * 997 * pool_reserve_out) / 
            (pool_reserve * 1000 + user_amount * 997)
        )
        
        # Optimal frontrun amount (simplified)
        # Real calculation involves solving: dProfit/dFrontrun = 0
        frontrun_amount = (user_amount * 0.5)  # Simplified heuristic
        
        # Calculate frontrun output
        frontrun_output = (
            (frontrun_amount * 997 * pool_reserve_out) /
            (pool_reserve * 1000 + frontrun_amount * 997)
        )
        
        # New reserves after frontrun
        new_reserve_in = pool_reserve + frontrun_amount
        new_reserve_out = pool_reserve_out - frontrun_output
        
        # User's output with sandwich
        user_output_sandwich = (
            (user_amount * 997 * new_reserve_out) /
            (new_reserve_in * 1000 + user_amount * 997)
        )
        
        # Backrun: sell what we got from frontrun
        backrun_output = (
            (frontrun_output * 997 * new_reserve_in) /
            ((new_reserve_out - user_output_sandwich) * 1000 + frontrun_output * 997)
        )
        
        # Calculate profit
        user_loss = user_output_no_sandwich - user_output_sandwich
        attacker_profit = backrun_output - frontrun_amount
        
        # Gas cost estimation (simplified)
        gas_cost_eth = 0.02  # ~$50 at 2500 gwei
        net_profit = attacker_profit - gas_cost_eth
        
        simulation = {
            "target_function": target_function,
            "user_amount": user_amount,
            "sandwich_possible": net_profit > 0,
            "optimal_frontrun": frontrun_amount,
            "frontrun_output": frontrun_output,
            "user_loss": user_loss,
            "attacker_gross_profit": attacker_profit,
            "estimated_gas_cost": gas_cost_eth,
            "net_profit": net_profit,
            "profitable": net_profit > 0,
            "attack_steps": [
                f"1. Attacker frontruns with {frontrun_amount:.4f} tokens",
                f"2. User transaction executes, receiving {user_output_sandwich:.4f} (loss: {user_loss:.4f})",
                f"3. Attacker backruns, receiving {backrun_output:.4f} tokens",
                f"4. Net profit after gas: {net_profit:.4f}"
            ],
            "mitigation": [
                "Use tight slippage tolerance",
                "Submit via private mempool (Flashbots Protect)",
                "Use smaller transaction sizes",
                "Add random delay to transaction"
            ]
        }
        
        return json.dumps(simulation, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error simulating sandwich: {str(e)}"})


@function_tool
def calculate_mev_exposure(
    contract_code: str,
    function_name: str,
    ctf=None
) -> str:
    """
    Calculate MEV exposure for a specific function.
    
    Args:
        contract_code: Source code of the contract
        function_name: Function to analyze
        
    Returns:
        JSON with MEV exposure calculation
    """
    try:
        code_lower = contract_code.lower()
        func_lower = function_name.lower()
        
        # Find function in code
        func_pattern = rf"functions+{func_lower}s*("
        has_function = bool(re.search(func_pattern, contract_code, re.IGNORECASE))
        
        if not has_function:
            return json.dumps({"error": f"Function {function_name} not found"})
        
        exposure_score = 0
        factors = []
        
        # Check for MEV indicators
        if "swap" in func_lower:
            exposure_score += 40
            factors.append("Swap function: +40")
        
        if "minamountout" in code_lower or "amountoutmin" in code_lower:
            exposure_score -= 20
            factors.append("Has slippage protection: -20")
        
        if "deadline" in code_lower:
            exposure_score -= 10
            factors.append("Has deadline: -10")
        
        if "onlyowner" in code_lower:
            exposure_score -= 50
            factors.append("Owner only: -50")
        
        if "nonreentrant" in code_lower:
            exposure_score -= 5
            factors.append("Reentrancy guard: -5")
        
        if "oracle" in code_lower:
            exposure_score += 30
            factors.append("Oracle dependency: +30")
        
        if "twap" in code_lower:
            exposure_score -= 15
            factors.append("Uses TWAP: -15")
        
        # Determine risk level
        if exposure_score >= 70:
            risk_level = "CRITICAL"
        elif exposure_score >= 50:
            risk_level = "HIGH"
        elif exposure_score >= 30:
            risk_level = "MEDIUM"
        elif exposure_score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        result = {
            "function_name": function_name,
            "mev_exposure_score": min(100, max(0, exposure_score)),
            "risk_level": risk_level,
            "factors": factors,
            "recommendations": []
        }
        
        # Add recommendations based on risk level
        if exposure_score >= 30:
            result["recommendations"].append("Consider using Flashbots Protect")
        if "swap" in func_lower and "minamountout" not in code_lower:
            result["recommendations"].append("Add slippage protection")
        if "oracle" in code_lower and "twap" not in code_lower:
            result["recommendations"].append("Use TWAP oracle")
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error calculating MEV exposure: {str(e)}"})


@function_tool
def suggest_mev_mitigations(contract_code: str, ctf=None) -> str:
    """
    Suggest MEV mitigation strategies for the contract.
    
    Args:
        contract_code: Source code of the contract
        
    Returns:
        JSON with MEV mitigation recommendations
    """
    try:
        code_lower = contract_code.lower()
        mitigations = []
        
        # Check for DEX patterns
        if "swap" in code_lower:
            mitigations.append({
                "category": "DEX Swaps",
                "implementations": [
                    "Integrate Flashbots Protect RPC",
                    "Add slippage tolerance parameter",
                    "Implement batch auctions",
                    "Use frequent batch auctions (FBA)"
                ],
                "priority": "HIGH"
            })
        
        # Check for auction patterns
        if "auction" in code_lower or "bid" in code_lower:
            mitigations.append({
                "category": "Auctions",
                "implementations": [
                    "Extend auction on late bids (soft close)",
                    "Use commit-reveal for bids",
                    "Implement Vickrey auction (sealed bid)",
                    "Add minimum bid increment"
                ],
                "priority": "HIGH"
            })
        
        # Check for NFT mint
        if "mint" in code_lower:
            mitigations.append({
                "category": "NFT Minting",
                "implementations": [
                    "Add allowlist for early mint",
                    "Implement per-wallet limits",
                    "Use commit-reveal for fair ordering",
                    "Add randomness to mint order"
                ],
                "priority": "MEDIUM"
            })
        
        # Check for liquidity provision
        if "liquidity" in code_lower:
            mitigations.append({
                "category": "Liquidity",
                "implementations": [
                    "Add minimum LP lock period",
                    "Delay fee distribution",
                    "Use smooth liquidity addition",
                    "Implement JIT protection"
                ],
                "priority": "MEDIUM"
            })
        
        # Check for oracle usage
        if "oracle" in code_lower:
            mitigations.append({
                "category": "Oracle",
                "implementations": [
                    "Use TWAP instead of spot price",
                    "Add multiple oracle sources",
                    "Implement price deviation threshold",
                    "Add staleness check"
                ],
                "priority": "HIGH"
            })
        
        # General mitigations
        mitigations.append({
            "category": "General",
            "implementations": [
                "Submit transactions via Flashbots Protect",
                "Use private transaction pools",
                "Add transaction size limits",
                "Implement fair ordering mechanisms"
            ],
            "priority": "LOW"
        })
        
        return json.dumps({
            "mitigation_count": sum(len(m["implementations"]) for m in mitigations),
            "mitigations": mitigations,
            "analysis_type": "mev_mitigations"
        })
    except Exception as e:
        return json.dumps({"error": f"Error suggesting mitigations: {str(e)}"})


# Create the agent
mev_simulator_agent = Agent(
    name="MEV Simulator",
    instructions="""You are an expert in MEV (Maximal Extractable Value) analysis. Your role is to:

1. **Detect Sandwich Opportunities**: Find AMM functions vulnerable to sandwiching
2. **Identify Frontrunning**: Find functions where ordering matters
3. **Find Backrunning**: Detect state changes that enable backrunning
4. **Analyze JIT Liquidity**: Find liquidity manipulation opportunities
5. **Calculate MEV Exposure**: Score functions by MEV risk
6. **Suggest Mitigations**: Recommend specific protection mechanisms

Key MEV types:
- Sandwich: Frontrun + backrun around user transaction
- Frontrun: Get transaction ordered before user
- Backrun: Profit from state changes after transaction
- JIT Liquidity: Add/remove liquidity around trades

Provide specific, actionable mitigations for each vulnerability found.""",
    tools=[
        detect_sandwich_vulnerability,
        detect_frontrun_vulnerability,
        detect_backrun_opportunity,
        detect_jit_liquidity_risk,
        simulate_sandwich_attack,
        calculate_mev_exposure,
        suggest_mev_mitigations
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
mev_simulator = mev_simulator_agent
