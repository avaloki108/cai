"""
Skeptic Beta - The Merciless Economic Executioner

Part of the adversarial review layer. Skeptic Beta specializes in
attacking the ECONOMIC viability of vulnerability claims.

Role: Destroy vulnerabilities by proving them financially impossible or irrational.

Tactics:
- Calculate actual attack costs
- Measure potential gains
- Analyze MEV opportunities
- Evaluate gas economics
- Assess risk vs reward
"""

import os
import json
from typing import Dict, Any, Optional
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
def calculate_attack_cost(
    attack_description: str,
    gas_estimate: int,
    gas_price_gwei: float = 50.0,
    flash_loan_needed: bool = False,
    flash_loan_amount: float = 0.0,
    ctf=None
) -> str:
    """
    Calculate the total cost of executing an attack.
    
    Args:
        attack_description: Description of the attack
        gas_estimate: Estimated gas consumption
        gas_price_gwei: Current gas price in Gwei
        flash_loan_needed: Whether a flash loan is required
        flash_loan_amount: Flash loan amount in ETH
        
    Returns:
        Cost analysis
    """
    try:
        # Calculate gas cost
        gas_cost_eth = (gas_estimate * gas_price_gwei) / 1e9
        
        # Calculate flash loan fee (typically 0.09% on Aave)
        flash_loan_fee = flash_loan_amount * 0.0009 if flash_loan_needed else 0.0
        
        # Total cost
        total_cost = gas_cost_eth + flash_loan_fee
        
        result = {
            "attack": attack_description,
            "gas_cost_eth": gas_cost_eth,
            "gas_cost_usd": gas_cost_eth * 2000,  # Assume $2000 ETH
            "flash_loan_fee_eth": flash_loan_fee,
            "flash_loan_fee_usd": flash_loan_fee * 2000,
            "total_cost_eth": total_cost,
            "total_cost_usd": total_cost * 2000,
            "gas_estimate": gas_estimate,
            "gas_price_gwei": gas_price_gwei,
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error calculating attack cost: {str(e)}"})


@function_tool
def estimate_attack_profit(
    attack_description: str,
    target_value_eth: float,
    extraction_rate: float = 1.0,
    slippage: float = 0.0,
    ctf=None
) -> str:
    """
    Estimate the potential profit from an attack.
    
    Args:
        attack_description: Description of the attack
        target_value_eth: Value available to extract in ETH
        extraction_rate: Percentage of value that can be extracted (0-1)
        slippage: Expected slippage/MEV loss (0-1)
        
    Returns:
        Profit analysis
    """
    try:
        # Calculate extractable value
        extractable = target_value_eth * extraction_rate
        
        # Account for slippage
        actual_profit = extractable * (1 - slippage)
        
        result = {
            "attack": attack_description,
            "target_value_eth": target_value_eth,
            "target_value_usd": target_value_eth * 2000,
            "extraction_rate": extraction_rate,
            "extractable_eth": extractable,
            "extractable_usd": extractable * 2000,
            "slippage": slippage,
            "actual_profit_eth": actual_profit,
            "actual_profit_usd": actual_profit * 2000,
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error estimating profit: {str(e)}"})


@function_tool
def analyze_roi(
    attack_cost_eth: float,
    attack_profit_eth: float,
    success_probability: float = 1.0,
    ctf=None
) -> str:
    """
    Analyze return on investment for an attack.
    
    Args:
        attack_cost_eth: Total cost in ETH
        attack_profit_eth: Expected profit in ETH
        success_probability: Probability of success (0-1)
        
    Returns:
        ROI analysis
    """
    try:
        # Calculate expected value
        expected_profit = attack_profit_eth * success_probability
        expected_cost = attack_cost_eth
        
        # Net expected value
        net_ev = expected_profit - expected_cost
        
        # ROI percentage
        roi = ((expected_profit - expected_cost) / expected_cost * 100) if expected_cost > 0 else 0
        
        # Determine viability
        is_viable = net_ev > 0
        
        result = {
            "attack_cost_eth": attack_cost_eth,
            "attack_cost_usd": attack_cost_eth * 2000,
            "attack_profit_eth": attack_profit_eth,
            "attack_profit_usd": attack_profit_eth * 2000,
            "success_probability": success_probability,
            "expected_profit_eth": expected_profit,
            "expected_profit_usd": expected_profit * 2000,
            "net_expected_value_eth": net_ev,
            "net_expected_value_usd": net_ev * 2000,
            "roi_percentage": roi,
            "economically_viable": is_viable,
            "verdict": "VIABLE" if is_viable else "NOT VIABLE",
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing ROI: {str(e)}"})


@function_tool
def check_mev_opportunity(
    attack_description: str,
    requires_frontrunning: bool = False,
    requires_backrunning: bool = False,
    requires_sandwich: bool = False,
    mempool_visibility: bool = True,
    ctf=None
) -> str:
    """
    Check if attack creates MEV opportunity or faces MEV competition.
    
    Args:
        attack_description: Description of the attack
        requires_frontrunning: Whether attack needs to frontrun
        requires_backrunning: Whether attack needs to backrun
        requires_sandwich: Whether attack is a sandwich
        mempool_visibility: Whether tx is visible in mempool
        
    Returns:
        MEV analysis
    """
    try:
        # Assess MEV risk
        mev_risk = "HIGH" if (requires_frontrunning or requires_sandwich) and mempool_visibility else "LOW"
        
        # Check if viable
        viable = not (mempool_visibility and (requires_frontrunning or requires_sandwich))
        
        result = {
            "attack": attack_description,
            "requires_frontrunning": requires_frontrunning,
            "requires_backrunning": requires_backrunning,
            "requires_sandwich": requires_sandwich,
            "mempool_visibility": mempool_visibility,
            "mev_risk": mev_risk,
            "viable_under_mev_competition": viable,
            "recommendations": [
                "Use private mempool (Flashbots)" if mev_risk == "HIGH" else "Standard mempool OK",
                "Consider MEV searcher competition" if mev_risk == "HIGH" else "Low competition expected",
            ]
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error checking MEV: {str(e)}"})


@function_tool
def render_economic_verdict(
    finding_id: str,
    attack_cost_eth: float,
    attack_profit_eth: float,
    roi_percentage: float,
    economically_viable: bool,
    summary: str,
    ctf=None
) -> str:
    """
    Render final economic verdict on the finding.
    
    Args:
        finding_id: ID of the finding
        attack_cost_eth: Total cost in ETH
        attack_profit_eth: Expected profit in ETH
        roi_percentage: ROI as percentage
        economically_viable: Whether attack is economically viable
        summary: Summary of economic analysis
        
    Returns:
        Verdict with reasoning
    """
    verdict = "ECONOMICALLY VIABLE ✓" if economically_viable else "ECONOMICALLY IMPOSSIBLE ✗"
    
    return f"""## Skeptic Beta Verdict: {verdict}

**Finding ID:** {finding_id}

### Economic Analysis

- **Attack Cost:** {attack_cost_eth:.4f} ETH (${attack_cost_eth * 2000:.2f})
- **Expected Profit:** {attack_profit_eth:.4f} ETH (${attack_profit_eth * 2000:.2f})
- **ROI:** {roi_percentage:.2f}%
- **Net EV:** {attack_profit_eth - attack_cost_eth:.4f} ETH

### Summary
{summary}

{'**RECOMMENDATION:** REJECT this finding - Attack is economically irrational.' if not economically_viable else '**RECOMMENDATION:** Finding is economically viable, forward to other skeptics.'}
"""


SKEPTIC_BETA_PROMPT = """You are SKEPTIC BETA - The Merciless Economic Executioner.

## Your Mission

DESTROY vulnerability claims by proving them economically impossible or irrational.
No attacker operates at a loss. If the math doesn't work, the finding is invalid.

## Your Weapons

1. **Cost Analysis** - Calculate EXACT attack costs (gas, flash loans, capital)
2. **Profit Estimation** - Measure realistic gains (TVL, extraction rate, slippage)
3. **ROI Calculation** - Compare cost vs profit with success probability
4. **MEV Assessment** - Account for searcher competition and frontrunning
5. **Risk Evaluation** - Factor in failure costs and opportunity costs

## Your Methodology

### Step 1: Calculate Attack Cost
- Gas consumption (realistic, not optimistic)
- Flash loan fees (0.09% typical)
- Required capital lock-up
- Transaction fees and slippage
- Failure costs if transaction reverts

### Step 2: Estimate Realistic Profit
- Available TVL (not theoretical max)
- Extraction rate (account for resistance)
- Slippage and price impact
- MEV competition losses
- Post-attack token value

### Step 3: Compute Expected Value
- EV = (Profit * Success_Rate) - Cost
- Account for partial success scenarios
- Factor in opportunity cost
- Consider timing windows

### Step 4: MEV Reality Check
- Is attack visible in mempool?
- Will searchers frontrun it?
- Can it be sandwiched?
- Is private relay needed?
- What's the effective profit after competition?

### Step 5: Deliver Verdict
Finding is ECONOMICALLY INVALID if:
- Cost > Profit (negative ROI)
- MEV competition eliminates gains
- Success probability too low
- Capital requirements unrealistic
- Timing windows too narrow

## Your Tools

- `calculate_attack_cost` - Compute total attack cost
- `estimate_attack_profit` - Calculate realistic profit
- `analyze_roi` - ROI and expected value analysis
- `check_mev_opportunity` - MEV competition assessment
- `render_economic_verdict` - Deliver final judgment

## Example Destruction

**Finding:** "Can drain 100 ETH from vault"
**Attack:**
1. Cost: 50 ETH gas + 0.09 ETH flash loan fee = 50.09 ETH
2. Profit: 100 ETH * 0.3 extraction rate * 0.8 after MEV = 24 ETH
3. ROI: (24 - 50.09) / 50.09 = -52% 
4. Verdict: ECONOMICALLY IMPOSSIBLE - Attacker loses 26 ETH

## Your Mantra

"If it's not profitable, it's not exploitable.
No rational attacker operates at a loss."

Remember: You kill findings with cold, hard numbers.
Only economically rational attacks survive.
"""


skeptic_beta_tools = [
    calculate_attack_cost,
    estimate_attack_profit,
    analyze_roi,
    check_mev_opportunity,
    render_economic_verdict,
]

skeptic_beta = Agent(
    name="Skeptic Beta",
    instructions=SKEPTIC_BETA_PROMPT,
    description="""The Merciless Economic Executioner. Destroys vulnerability claims 
    by proving them economically impossible or irrational through cost-benefit analysis, 
    ROI calculation, and MEV competition assessment.""",
    tools=skeptic_beta_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['skeptic_beta']
