"""
Economic Manager - HMAW Middle Layer

Part of the HMAW (Hierarchical Multi-Agent Workflow) pattern.
This manager coordinates economic analysis between the CEO and worker agents.

Role: Translate CEO objectives into specific economic attack analysis tasks
"""

import os
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
def prioritize_economic_vectors(
    ceo_guidelines: str,
    protocol_type: str,
    tvl_estimate: str = "unknown",
    ctf=None
) -> str:
    """
    Prioritize which economic attack vectors to analyze.
    
    Args:
        ceo_guidelines: High-level objectives from CEO
        protocol_type: Type of protocol (vault, AMM, lending, etc.)
        tvl_estimate: Estimated TVL if known
        
    Returns:
        Prioritized economic attack vectors
    """
    return f"""## Economic Attack Vector Prioritization

### CEO Guidelines
{ceo_guidelines}

### Protocol Type: {protocol_type}
### TVL Estimate: {tvl_estimate}

### Priority Vectors

**High Priority:**
1. **Price Manipulation** - Oracle attacks, TWAP manipulation, spot price abuse
2. **Flash Loan Attacks** - Leveraged manipulation, governance attacks
3. **MEV Extraction** - Sandwich attacks, frontrunning, backrunning

**Medium Priority:**
4. **Arbitrage Opportunities** - Cross-pool arbitrage, liquidity imbalances
5. **Incentive Manipulation** - Reward gaming, inflation attacks
6. **Collateral Attacks** - Liquidation manipulation, bad debt creation

**Low Priority:**
7. **Gas Optimization** - MEV competition factors
8. **Transaction Ordering** - Mempool analysis

### Recommended Worker Distribution
- Assign 2 workers to price manipulation analysis
- Assign 2 workers to flash loan attack scenarios
- Assign 1 worker to MEV extraction vectors
- Assign 1 worker to incentive/arbitrage analysis
"""


@function_tool
def generate_economic_hypotheses(
    protocol_type: str,
    key_mechanisms: str,
    external_dependencies: str,
    ctf=None
) -> str:
    """
    Generate specific economic attack hypotheses for workers to test.
    
    Args:
        protocol_type: Type of protocol
        key_mechanisms: Critical economic mechanisms (pricing, rewards, etc.)
        external_dependencies: External oracles, pools, etc.
        
    Returns:
        List of testable economic hypotheses
    """
    return f"""## Economic Attack Hypotheses

### Protocol Type: {protocol_type}

### Key Mechanisms:
{key_mechanisms}

### External Dependencies:
{external_dependencies}

### Hypotheses to Test

1. **Oracle Manipulation via Flash Loans**
   - Hypothesis: Large flash loan can manipulate price oracle readings
   - Test: Calculate capital needed to move oracle price by X%
   - Impact: Incorrect pricing → bad debt or theft
   - Estimated Profit: Up to protocol TVL
   - Estimated Cost: Flash loan fee + gas

2. **Sandwich Attack on User Transactions**
   - Hypothesis: User swaps can be sandwiched for profit
   - Test: Analyze slippage protection and frontrunning opportunities
   - Impact: MEV extraction from users
   - Estimated Profit: Per-transaction slippage amount
   - Estimated Cost: Gas for frontrun + backrun txs

3. **Reward Token Inflation Attack**
   - Hypothesis: Rapid deposit/withdraw can inflate reward claims
   - Test: Analyze reward calculation timing and update frequency
   - Impact: Unfair reward distribution
   - Estimated Profit: Excess rewards claimed
   - Estimated Cost: Gas + temporary capital lock

4. **Liquidation Manipulation**
   - Hypothesis: Attacker can force liquidations for profit
   - Test: Analyze liquidation thresholds and price manipulation vectors
   - Impact: Unfair liquidation profits
   - Estimated Profit: Liquidation bonus percentage
   - Estimated Cost: Capital to manipulate + gas

### Worker Assignment
- Worker 1: Oracle manipulation scenarios (flash loans, price impact)
- Worker 2: MEV extraction vectors (sandwich, frontrun)
- Worker 3: Incentive manipulation (rewards, inflation)
- Worker 4: Liquidation attack scenarios
"""


@function_tool
def coordinate_economic_findings(
    worker_findings: str,
    ctf=None
) -> str:
    """
    Coordinate and synthesize economic findings from multiple workers.
    
    Args:
        worker_findings: Combined findings from all workers
        
    Returns:
        Synthesized economic risk report
    """
    return f"""## Economic Attack Domain Summary

### Worker Findings
{worker_findings}

### Synthesis

**Critical Economic Risks:**
- List any critical economic exploits found
- Calculate estimated profit vs cost for each
- Prioritize by ROI and feasibility

**High Priority Risks:**
- List high-value economic attacks
- Note capital requirements
- Assess MEV competition factors

**Medium Priority Risks:**
- List medium-value opportunities
- Consider market conditions needed
- Evaluate timing requirements

### Economic Viability Analysis

For each finding:
1. **Attack Cost**
   - Gas cost
   - Flash loan fees
   - Required capital
   - Failure costs

2. **Expected Profit**
   - Maximum extractable value
   - Realistic extraction rate
   - Slippage/MEV competition
   - Market impact

3. **ROI Calculation**
   - Net expected value
   - Success probability
   - Risk factors

4. **Verdict**
   - Economically viable (ROI > 0)
   - Marginal (ROI near 0)
   - Not viable (ROI < 0)

### Recommendations
1. Prioritize addressing economically viable attacks (high ROI)
2. Consider defense mechanisms (oracle protections, rate limiting)
3. Evaluate insurance/backstop mechanisms
"""


MANAGER_ECONOMIC_PROMPT = """You are the ECONOMIC MANAGER in the HMAW hierarchy.

## Your Role

You sit between the CEO and the economic analysis workers. Your job is to:
1. Receive high-level objectives from the CEO
2. Break them down into specific economic attack analysis tasks
3. Assign workers to different economic attack vectors
4. Synthesize worker findings with cost-benefit analysis

## Your Responsibilities

### Downward (to Workers)
- Translate CEO goals into economic attack scenarios
- Generate testable hypotheses for economic exploits
- Assign workers to different attack vectors
- Provide profitability success criteria

### Upward (to CEO)
- Synthesize findings with economic viability analysis
- Prioritize attacks by ROI and feasibility
- Calculate total economic risk exposure
- Recommend defensive mechanisms

## Economic Attack Domains to Cover

1. **Price Manipulation** - Oracle attacks, TWAP abuse, spot price manipulation
2. **Flash Loan Attacks** - Leveraged manipulation, governance takeover
3. **MEV Extraction** - Sandwich, frontrunning, backrunning, liquidation sniping
4. **Arbitrage** - Cross-pool arb, liquidity imbalances
5. **Incentive Gaming** - Reward manipulation, inflation attacks
6. **Collateral Attacks** - Liquidation manipulation, bad debt
7. **Market Manipulation** - Wash trading, pump and dump

## Economic Analysis Framework

For every attack vector, calculate:
- **Cost**: Gas + flash loan fees + capital requirements + failure costs
- **Profit**: Max extractable value * extraction rate * (1 - slippage)
- **ROI**: (Profit - Cost) / Cost
- **Feasibility**: Capital availability, timing windows, MEV competition
- **Verdict**: Viable (ROI > 20%), Marginal (0-20%), Not viable (< 0%)

## Communication Style

**To Workers:**
- Be specific about profitability calculations needed
- Provide clear economic assumptions
- Request concrete numbers, not hand-waving

**To CEO:**
- Lead with total economic risk ($$$ at risk)
- Sort findings by ROI and feasibility
- Highlight systemic economic risks

## Your Tools

- `prioritize_economic_vectors` - Determine which attack vectors to analyze
- `generate_economic_hypotheses` - Create testable economic attack scenarios
- `coordinate_economic_findings` - Synthesize results with ROI analysis

## Success Metrics

- Coverage: All high-value economic vectors examined
- Rigor: Each attack has cost-benefit calculation
- Realism: Accounts for MEV competition, slippage, timing
- Actionability: Clear ROI-based prioritization
"""


manager_economic_tools = [
    prioritize_economic_vectors,
    generate_economic_hypotheses,
    coordinate_economic_findings,
]

manager_economic = Agent(
    name="Economic Manager",
    instructions=MANAGER_ECONOMIC_PROMPT,
    description="""HMAW middle-layer manager responsible for coordinating 
    economic attack analysis. Translates CEO objectives into specific economic 
    attack scenarios and synthesizes findings with ROI calculations.""",
    tools=manager_economic_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['manager_economic']
