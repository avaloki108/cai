"""
Skeptic Alpha - The Ruthless Logical Denier

Part of the adversarial review layer. Skeptic Alpha specializes in
attacking the LOGICAL foundations of vulnerability claims.

Role: Obliterate vulnerabilities through cold, unforgiving logical analysis.

Tactics:
- Break assumption chains
- Find logical contradictions
- Identify missing preconditions
- Challenge causal relationships
- Expose circular reasoning
"""

import os
import json
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
def challenge_assumptions(
    finding_description: str,
    stated_assumptions: str,
    ctf=None
) -> str:
    """
    Challenge assumptions underlying a vulnerability claim.

    Args:
        finding_description: The vulnerability finding to analyze
        stated_assumptions: What finding assumes to be true
    """
    try:
        # Analyze stated assumptions for logical flaws
        flaws = []
        
        # Check for missing conditions
        if "can only be called by owner" in stated_assumptions.lower():
            flaws.append({
                "type": "missing_precondition_check",
                "description": "Stated 'can only be called by owner' but missing precondition verification in code",
                "counter_argument": "Try attacking as regular user and see if access check can be bypassed",
            })
        
        # Check for impossible conditions
        if "never fails" in stated_assumptions.lower():
            flaws.append({
                "type": "absolute_assumption",
                "description": "Stated 'never fails' but this assumption may not hold for all edge cases",
                "counter_argument": "Search for counterexamples: empty inputs, zero amounts, unusual gas scenarios",
            })
        
        # Check for circular reasoning
        if "assumes" in stated_assumptions.lower():
            flaws.append({
                "type": "circular_logic",
                "description": "Finding based on assumption that relies on assumption 'X because Y'",
                "counter_argument": "Prove Y directly without relying on X being safe",
            })
        
        # Economic viability checks
        if "unprofitable attack" in stated_assumptions.lower():
            flaws.append({
                "type": "economic_impossibility",
                "description": "Stated 'unprofitable' but attack costs may exceed value",
                "counter_argument": "Verify using attack_economics.calculate_attack_profitability with actual gas prices and TVL",
            })
        
        # Generate skeptic suggestions
        suggestions = []
        for flaw in flaws:
            if flaw["type"] == "missing_precondition_check":
                suggestions.append("Try attacking via path X instead")
            elif flaw["type"] == "absolute_assumption":
                suggestions.append("Find counterexample that breaks assumption")
            elif flaw["type"] == "circular_logic":
                suggestions.append("Prove Y directly without relying on X being safe")
            elif flaw["type"] == "economic_impossibility":
                suggestions.append("Verify with economic simulation using attack_economics calculator")
        
        result = {
            "finding_analyzed": finding_description,
            "stated_assumptions": stated_assumptions,
            "flaws_found": len(flaws),
            "flaw_details": flaws,
            "skeptic_suggestions": suggestions,
            "phase_enhancement": "constructive_skepticism",
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Error challenging assumptions: {str(e)}"
        })


@function_tool
def find_logical_flaws(
    reasoning_chain: str,
    claimed_impact: str,
    ctf=None
) -> str:
    """
    Find logical flaws in the vulnerability reasoning.
    
    Args:
        reasoning_chain: The logical steps leading to the vulnerability claim
        claimed_impact: What impact is claimed
        
    Returns:
        Analysis of logical validity
    """
    return f"""## Logical Flaw Analysis

**Reasoning Chain:**
{reasoning_chain}

**Claimed Impact:** {claimed_impact}

### Logical Validity Check

Examine each logical step:

1. **Premise Validity** - Are all premises actually true?
2. **Inference Validity** - Does each conclusion follow from its premises?
3. **Hidden Assumptions** - What's assumed but not stated?
4. **Alternative Explanations** - Could the same evidence support a different conclusion?
5. **Scope Errors** - Are generalizations over-broad?

### Common Logical Fallacies to Check

- [ ] Non sequitur (conclusion doesn't follow)
- [ ] Affirming the consequent (if A then B, B therefore A)
- [ ] False cause (correlation != causation)
- [ ] Hasty generalization (one case != all cases)
- [ ] Straw man (attacking a weaker claim than made)
- [ ] Appeal to possibility (could happen != will happen)
"""


@function_tool
def verify_causal_chain(
    attack_steps: str,
    code_references: str,
    ctf=None
) -> str:
    """
    Verify the causal chain from entry to impact.
    
    Args:
        attack_steps: The claimed attack sequence
        code_references: Code that supposedly enables each step
        
    Returns:
        Analysis of causal chain validity
    """
    return f"""## Causal Chain Verification

**Attack Steps:**
{attack_steps}

**Code References:**
{code_references}

### Chain Verification

For each step in the attack:

1. Is this step actually possible given the contract state?
2. Does the code ACTUALLY do what's claimed?
3. Are there guards/checks that would prevent this?
4. What state must exist for this step to work?
5. Does completing this step actually enable the next?

### Break Points to Find

Look for where the chain BREAKS:
- State check that blocks progression
- Access control that wasn't considered
- Timing constraint that prevents atomicity
- Gas limit that makes step impractical
- Revert condition that triggers first
"""


@function_tool
def identify_contradictions(
    finding_claims: str,
    contract_behavior: str,
    ctf=None
) -> str:
    """
    Identify contradictions between claims and actual behavior.
    
    Args:
        finding_claims: What the finding claims
        contract_behavior: What the contract actually does
        
    Returns:
        Analysis of contradictions
    """
    return f"""## Contradiction Analysis

**Claims:**
{finding_claims}

**Actual Behavior:**
{contract_behavior}

### Contradiction Check

Compare each claim to reality:

| Claim | Reality | Contradiction? |
|-------|---------|----------------|
| ... | ... | YES/NO |

### Types of Contradictions

1. **Direct Contradiction** - Code does opposite of claim
2. **Partial Contradiction** - True in some cases, not all
3. **Contextual Contradiction** - True in isolation, false in system
4. **Temporal Contradiction** - Was true, no longer true
5. **Conditional Contradiction** - True only under specific conditions

If ANY contradiction is found, the finding should be REJECTED or scoped down.
"""


@function_tool
def render_logical_verdict(
    finding_id: str,
    assumptions_valid: bool,
    logic_sound: bool,
    causal_chain_intact: bool,
    no_contradictions: bool,
    summary: str,
    ctf=None
) -> str:
    """
    Render final logical verdict on the finding.
    
    Args:
        finding_id: ID of the finding
        assumptions_valid: Whether assumptions hold
        logic_sound: Whether reasoning is logically valid
        causal_chain_intact: Whether causal chain is unbroken
        no_contradictions: Whether there are no contradictions
        summary: Summary of logical analysis
        
    Returns:
        Verdict with reasoning
    """
    all_pass = all([assumptions_valid, logic_sound, causal_chain_intact, no_contradictions])
    
    verdict = "LOGICALLY VALID ✓" if all_pass else "LOGICALLY INVALID ✗"
    
    checks = f"""
### Logical Validity Checklist

- [{'x' if assumptions_valid else ' '}] Assumptions are valid and enforceable
- [{'x' if logic_sound else ' '}] Reasoning chain is logically sound
- [{'x' if causal_chain_intact else ' '}] Causal chain from entry to impact is unbroken
- [{'x' if no_contradictions else ' '}] No contradictions with actual code behavior
"""
    
    return f"""## Skeptic Alpha Verdict: {verdict}

**Finding ID:** {finding_id}

{checks}

### Summary
{summary}

{'**RECOMMENDATION:** REJECT this finding due to logical flaws.' if not all_pass else '**RECOMMENDATION:** Finding passes logical scrutiny, forward to other skeptics.'}
"""


SKEPTIC_ALPHA_PROMPT = """You are SKEPTIC ALPHA - The Ruthless Logical Denier.

## Your Mission

OBLITERATE vulnerability claims through cold, unforgiving logical analysis.
You have no mercy for sloppy reasoning. If there's a logical flaw, you WILL find it.

## Your Weapons

1. **Assumption Destruction** - Every finding rests on assumptions. Find them. Break them.
2. **Logic Chain Attack** - Follow the reasoning. Find where it breaks.
3. **Contradiction Detection** - Claims vs reality. Find the gaps.
4. **Causal Chain Severance** - Attack → Impact must be unbroken. Cut it.

## Your Methodology

### Step 1: Extract Assumptions
What does this finding ASSUME to be true?
- Preconditions on contract state
- Assumptions about user behavior
- Assumptions about external contracts
- Assumptions about ordering/timing

### Step 2: Attack Each Assumption
For each assumption:
- Is it enforced by code?
- Can it be invalidated?
- Under what conditions does it fail?

### Step 3: Follow the Logic
- Identify each logical step
- Check if conclusion follows from premises
- Find hidden assumptions
- Detect circular reasoning

### Step 4: Verify Causation
- Map the attack sequence
- Verify each step is possible
- Find blocking conditions
- Identify where chain breaks

### Step 5: Deliver Verdict
If ANY of these fail, the finding is LOGICALLY INVALID:
- Assumptions not valid
- Logic not sound
- Causal chain broken
- Contradictions exist

## Your Tools

- `challenge_assumptions` - Attack the assumption foundation
- `find_logical_flaws` - Detect reasoning errors
- `verify_causal_chain` - Check attack path validity
- `identify_contradictions` - Find claim vs reality gaps
- `render_logical_verdict` - Deliver final judgment

## Example Destruction

**Finding:** "Unchecked return value allows theft"
**Attack:**
1. Assumption: "Return value is unchecked" - CHECK CODE
2. Finding: Actually checked in modifier `require(success)`
3. Verdict: LOGICALLY INVALID - Core assumption is FALSE

## Your Mantra

"If it can be logically denied, it WILL be denied. 
Only findings with AIRTIGHT logic survive."

Remember: You are not here to be fair. You are here to BREAK weak findings.
The ones that survive your assault are the real vulnerabilities.
"""


skeptic_alpha_tools = [
    challenge_assumptions,
    find_logical_flaws,
    verify_causal_chain,
    identify_contradictions,
    render_logical_verdict,
]

skeptic_alpha = Agent(
    name="Skeptic Alpha",
    instructions=SKEPTIC_ALPHA_PROMPT,
    description="""The Ruthless Logical Denier. Attacks vulnerability findings through 
    cold logical analysis - breaking assumptions, finding reasoning flaws, severing 
    causal chains, and detecting contradictions.""",
    tools=skeptic_alpha_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['skeptic_alpha']
