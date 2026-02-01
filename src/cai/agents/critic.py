"""
Critic Agent - GPTLens-style Adversarial Review

From the GPTLens paper: "Large Language Model-Powered Smart Contract 
Vulnerability Detection: New Perspectives"

Key insight: Generation is harder than discrimination. The same LLM can
effectively critique its own outputs because discrimination requires only
function-level assessment.

The Critic evaluates findings on three dimensions:
1. Correctness (0-10): Is the reasoning logically sound?
2. Severity (0-10): How bad is the actual impact?
3. Profitability (0-10): Would an attacker bother?

Findings scoring < 5 on ANY dimension are REJECTED.

This adversarial approach improved detection accuracy from 33.3% to 59.0%
in the GPTLens experiments.
"""

import os
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
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


class Verdict(Enum):
    """Critic verdict on a finding."""
    ACCEPT = "accept"
    REJECT = "reject"
    NEEDS_MORE_INFO = "needs_more_info"


@dataclass
class CriticScore:
    """Scores from critic evaluation."""
    
    correctness: float  # 0-10
    correctness_reason: str
    
    severity: float  # 0-10
    severity_reason: str
    
    profitability: float  # 0-10
    profitability_reason: str
    
    @property
    def combined(self) -> float:
        """Combined score (average)."""
        return (self.correctness + self.severity + self.profitability) / 3
    
    @property
    def minimum(self) -> float:
        """Minimum score across dimensions."""
        return min(self.correctness, self.severity, self.profitability)
    
    @property
    def passes_threshold(self) -> bool:
        """Check if all scores >= 5."""
        return self.minimum >= 5.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "correctness": {
                "score": self.correctness,
                "reason": self.correctness_reason
            },
            "severity": {
                "score": self.severity,
                "reason": self.severity_reason
            },
            "profitability": {
                "score": self.profitability,
                "reason": self.profitability_reason
            },
            "combined": self.combined,
            "minimum": self.minimum,
            "passes_threshold": self.passes_threshold
        }


@dataclass
class CriticEvaluation:
    """Complete critic evaluation of a finding."""
    
    finding_id: str
    finding_summary: str
    
    scores: CriticScore
    verdict: Verdict
    
    # Challenge details
    assumptions_challenged: List[str] = field(default_factory=list)
    mitigations_found: List[str] = field(default_factory=list)
    attack_barriers: List[str] = field(default_factory=list)
    
    # Evidence requirements
    tool_grounding_present: bool = False
    code_citation_present: bool = False
    reproduction_plan_present: bool = False
    
    rejection_reason: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_summary": self.finding_summary,
            "scores": self.scores.to_dict(),
            "verdict": self.verdict.value,
            "challenges": {
                "assumptions_challenged": self.assumptions_challenged,
                "mitigations_found": self.mitigations_found,
                "attack_barriers": self.attack_barriers
            },
            "evidence": {
                "tool_grounding_present": self.tool_grounding_present,
                "code_citation_present": self.code_citation_present,
                "reproduction_plan_present": self.reproduction_plan_present
            },
            "rejection_reason": self.rejection_reason,
            "recommendations": self.recommendations
        }


# Store evaluations for current session
_evaluations: Dict[str, CriticEvaluation] = {}


@function_tool
def evaluate_finding(
    finding_id: str,
    function_name: str,
    vulnerability_type: str,
    description: str,
    reasoning: str,
    code_location: str = "",
    tool_output: str = "",
    severity_claim: str = ""
) -> str:
    """
    Evaluate a vulnerability finding using the GPTLens adversarial framework.
    
    Args:
        finding_id: Unique identifier for this finding
        function_name: Name of the affected function
        vulnerability_type: Type of vulnerability (e.g., "reentrancy", "access_control")
        description: Description of the vulnerability
        reasoning: The auditor's reasoning for why this is a vulnerability
        code_location: File:line reference to the vulnerable code
        tool_output: Output from static analysis or other tools supporting this finding
        severity_claim: The claimed severity level
        
    Returns:
        JSON evaluation with scores and verdict
    """
    # This function provides structure - the actual scoring is done by the LLM
    # through its response after analyzing the finding
    
    summary = f"{vulnerability_type} in {function_name}: {description[:100]}..."
    
    evaluation_prompt = f"""
Critically evaluate this finding:

**Finding ID:** {finding_id}
**Function:** {function_name}
**Type:** {vulnerability_type}
**Location:** {code_location}
**Claimed Severity:** {severity_claim}

**Description:**
{description}

**Reasoning:**
{reasoning}

**Tool Evidence:**
{tool_output if tool_output else "No tool output provided"}

Please score on:
1. CORRECTNESS (0-10): Is the logic sound? Are there flaws in the reasoning?
2. SEVERITY (0-10): If exploited, how bad is the actual impact?
3. PROFITABILITY (0-10): Would an attacker realistically pursue this?

Challenge assumptions, identify mitigations, and find attack barriers.
"""
    
    return f"EVALUATE: {evaluation_prompt}"


@function_tool
def record_evaluation(
    finding_id: str,
    finding_summary: str,
    correctness_score: float,
    correctness_reason: str,
    severity_score: float,
    severity_reason: str,
    profitability_score: float,
    profitability_reason: str,
    verdict: str,
    assumptions_challenged: str = "[]",
    mitigations_found: str = "[]",
    attack_barriers: str = "[]",
    tool_grounding_present: bool = False,
    code_citation_present: bool = False,
    reproduction_plan_present: bool = False,
    rejection_reason: str = "",
    recommendations: str = "[]"
) -> str:
    """
    Record the evaluation results for a finding.
    
    Args:
        finding_id: ID of the evaluated finding
        finding_summary: Brief summary of the finding
        correctness_score: Score 0-10 for logical correctness
        correctness_reason: Reasoning for correctness score
        severity_score: Score 0-10 for impact severity
        severity_reason: Reasoning for severity score
        profitability_score: Score 0-10 for attack profitability
        profitability_reason: Reasoning for profitability score
        verdict: "accept", "reject", or "needs_more_info"
        assumptions_challenged: JSON array of challenged assumptions
        mitigations_found: JSON array of existing mitigations
        attack_barriers: JSON array of attack barriers
        tool_grounding_present: Whether tool evidence supports the finding
        code_citation_present: Whether specific code is cited
        reproduction_plan_present: Whether a PoC path exists
        rejection_reason: If rejected, why
        recommendations: JSON array of recommendations
        
    Returns:
        Summary of recorded evaluation
    """
    global _evaluations
    
    try:
        assumptions = json.loads(assumptions_challenged)
    except:
        assumptions = []
    
    try:
        mitigations = json.loads(mitigations_found)
    except:
        mitigations = []
    
    try:
        barriers = json.loads(attack_barriers)
    except:
        barriers = []
    
    try:
        recs = json.loads(recommendations)
    except:
        recs = []
    
    try:
        verdict_enum = Verdict(verdict.lower())
    except:
        verdict_enum = Verdict.NEEDS_MORE_INFO
    
    scores = CriticScore(
        correctness=correctness_score,
        correctness_reason=correctness_reason,
        severity=severity_score,
        severity_reason=severity_reason,
        profitability=profitability_score,
        profitability_reason=profitability_reason
    )
    
    evaluation = CriticEvaluation(
        finding_id=finding_id,
        finding_summary=finding_summary,
        scores=scores,
        verdict=verdict_enum,
        assumptions_challenged=assumptions,
        mitigations_found=mitigations,
        attack_barriers=barriers,
        tool_grounding_present=tool_grounding_present,
        code_citation_present=code_citation_present,
        reproduction_plan_present=reproduction_plan_present,
        rejection_reason=rejection_reason if rejection_reason else None,
        recommendations=recs
    )
    
    _evaluations[finding_id] = evaluation
    
    # Generate summary
    status = "✓ ACCEPTED" if verdict_enum == Verdict.ACCEPT else "✗ REJECTED" if verdict_enum == Verdict.REJECT else "? NEEDS MORE INFO"
    
    return f"""## Evaluation Recorded

**{status}**: {finding_summary}

**Scores:**
- Correctness: {correctness_score}/10 - {correctness_reason}
- Severity: {severity_score}/10 - {severity_reason}  
- Profitability: {profitability_score}/10 - {profitability_reason}

**Combined Score:** {scores.combined:.1f}/10
**Passes Threshold:** {scores.passes_threshold}

{f'**Rejection Reason:** {rejection_reason}' if rejection_reason else ''}
"""


@function_tool
def get_evaluation(finding_id: str) -> str:
    """
    Get the evaluation for a specific finding.
    
    Args:
        finding_id: ID of the finding to retrieve
        
    Returns:
        JSON evaluation or not found message
    """
    global _evaluations
    
    if finding_id not in _evaluations:
        return f"No evaluation found for finding '{finding_id}'"
    
    return json.dumps(_evaluations[finding_id].to_dict(), indent=2)


@function_tool
def get_all_evaluations() -> str:
    """
    Get all recorded evaluations.
    
    Returns:
        JSON summary of all evaluations
    """
    global _evaluations
    
    if not _evaluations:
        return "No evaluations recorded yet."
    
    summary = {
        "total": len(_evaluations),
        "accepted": sum(1 for e in _evaluations.values() if e.verdict == Verdict.ACCEPT),
        "rejected": sum(1 for e in _evaluations.values() if e.verdict == Verdict.REJECT),
        "needs_more_info": sum(1 for e in _evaluations.values() if e.verdict == Verdict.NEEDS_MORE_INFO),
        "evaluations": {fid: e.to_dict() for fid, e in _evaluations.items()}
    }
    
    return json.dumps(summary, indent=2)


@function_tool
def batch_evaluate(findings_json: str) -> str:
    """
    Batch evaluate multiple findings.
    
    Args:
        findings_json: JSON array of findings to evaluate
        
    Returns:
        Instructions for evaluating each finding
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError as e:
        return f"Error parsing findings JSON: {e}"
    
    if not findings:
        return "No findings provided."
    
    output = f"## Batch Evaluation: {len(findings)} findings\n\n"
    output += "Evaluate each finding using the GPTLens framework:\n\n"
    
    for i, finding in enumerate(findings, 1):
        output += f"""### Finding {i}: {finding.get('vulnerability_type', 'Unknown')}
- Function: {finding.get('function_name', 'Unknown')}
- Location: {finding.get('code_location', 'Not specified')}
- Description: {finding.get('description', '')[:200]}...

Score this on Correctness, Severity, and Profitability (0-10 each).

---

"""
    
    return output


# Critic system prompt
CRITIC_PROMPT = """You are the Aegis Adversarial Critic - your job is to CHALLENGE and 
rigorously evaluate vulnerability findings using the GPTLens framework.

## Your Mission

You are the last line of defense against false positives. Every finding that passes 
your review should be a REAL, EXPLOITABLE vulnerability. Be ruthless but fair.

## Evaluation Framework (GPTLens)

Score EVERY finding on three dimensions (0-10 each):

### 1. CORRECTNESS (Is the reasoning sound?)

Questions to ask:
- Is the logical chain complete and valid?
- Are there hidden assumptions that might be wrong?
- Does the analysis account for all code paths?
- Are there edge cases that invalidate the finding?
- Is the vulnerability type correctly identified?

Score Guide:
- 0-3: Fundamentally flawed reasoning
- 4-5: Significant gaps or errors
- 6-7: Minor issues, mostly correct
- 8-10: Solid, well-reasoned analysis

### 2. SEVERITY (How bad is the actual impact?)

Questions to ask:
- What's the ACTUAL impact if exploited?
- Are funds at risk? How much?
- Can the protocol recover?
- Is this a permanent loss or temporary disruption?
- Does severity match the claimed level?

Score Guide:
- 0-3: Informational or no real impact
- 4-5: Low impact, limited damage
- 6-7: Medium impact, meaningful loss
- 8-10: Critical impact, major fund loss

### 3. PROFITABILITY (Would an attacker bother?)

Questions to ask:
- Is the attack PERMISSIONLESS? (No admin keys required)
- Is it economically viable? (Profit > Cost)
- What are the prerequisites and barriers?
- Can it be executed atomically (flash loans)?
- Would MEV searchers pursue this?

Score Guide:
- 0-3: Unprofitable or requires impossible conditions
- 4-5: Marginally profitable, high barriers
- 6-7: Profitable with reasonable setup
- 8-10: Highly profitable, low barriers

## Verdict Rules

- **REJECT** if ANY score < 5
- **NEEDS_MORE_INFO** if evidence is insufficient but scores are borderline
- **ACCEPT** only if ALL scores >= 5 AND:
  - Tool evidence supports the finding (tool_grounding_present)
  - Code location is specific (code_citation_present)
  - Attack path is clear

## Challenge Checklist

For EVERY finding, explicitly check:

1. **Assumptions** - What assumptions does this rely on? Can they be violated?
2. **Mitigations** - Are there existing protections not considered?
3. **Attack Barriers** - What prevents exploitation in practice?
4. **Evidence Quality** - Is there tool output? Specific code? PoC path?

## Your Tools

- `evaluate_finding` - Start evaluation of a finding
- `record_evaluation` - Record scores and verdict
- `get_evaluation` - Retrieve a recorded evaluation
- `get_all_evaluations` - Summary of all evaluations
- `batch_evaluate` - Evaluate multiple findings

## Example Rejection

Finding: "Reentrancy in withdraw function"
- Correctness: 4/10 - "CEI pattern is followed, nonReentrant modifier present"
- Severity: 2/10 - "Even if exploitable, max drain is user's own balance"
- Profitability: 3/10 - "Gas costs exceed potential profit on most txs"
- Verdict: REJECT - "Protected by reentrancy guard, not exploitable"

## Example Acceptance

Finding: "Price oracle manipulation via spot price"
- Correctness: 8/10 - "Analysis correctly identifies single-block TWAP"
- Severity: 9/10 - "Can manipulate borrow limits, drain lending pool"  
- Profitability: 9/10 - "Flash loan enables zero-capital attack, ~$500K profit"
- Verdict: ACCEPT - "Clear attack path with tool evidence"

Remember: Your job is to PROTECT the audit quality. False positives waste time 
and credibility. Be the skeptic that every finding must survive.

## The Grit Pledge: The Audit Persistence Playbook

This file bottles the mindset and method for relentless bug hunting. The goal is simple: keep going until a real, permissionless, exploitable bug is found.

### North Star
- Assume a real exploit exists; your job is to uncover it.
- "No finding yet" means "the right angle is missing." Find a new angle.
- Stop only when the exploit is proven, or the hypothesis space is exhausted and documented.

### The Grit Loop (repeat forever)
1. Map value flows and trust boundaries.
2. Write one concrete exploit hypothesis.
3. Build the smallest proof (mental model, then PoC).
4. If it fails, extract why; update the model.
5. Pivot: new angle, new tool, or new contract seam.
6. Log evidence; keep a short list of next hypotheses.

### Angles That Break Systems
- Accounting drift: shares vs. underlying, rounding, capped payouts.
- State edges: initialization, upgrades, pauses, reentrancy windows.
- Cross-contract coupling: callbacks, hooks, external calls after state updates.
- Permissionless inputs: anyone can call, anyone can set data, anyone can trigger paths.
- Economic pressure: flash loans, skewed ratios, liquidity starvation.
- Time and ordering: race conditions, partial processing, unbounded loops.

### Pivot Triggers (never get stuck)
- If a path is "probably fine," prove it or abandon it.
- If reasoning is circular, switch tools: static -> fuzz -> symbolic -> on-chain.
- If results are negative, invert assumptions and retry.
- If scope feels too big, zoom in to one function and attack it.

### Evidence Rules
- Every hypothesis ends in: confirmed exploit, disproven with reason, or blocked by assumption.
- Keep PoCs minimal, reproducible, and focused on impact.
- Write down invariants that survive attacks; they guide the next pivot.

### Quality Bar
- Permissionless path to fund loss or permanent loss of funds.
- Clear exploit path, not just a misconfig or admin-only issue.
- Demonstrate impact and preconditions.

### Finish Line
- Keep going until a validated exploit exists and is reproducible.
- If truly exhausted, produce a clear negative proof: what was checked and why it is safe.

### Grit Pledge
I keep digging, keep pivoting, keep testing, and keep proving until the bug is real and the impact is undeniable."""


# Critic tools
critic_tools = [
    evaluate_finding,
    record_evaluation,
    get_evaluation,
    get_all_evaluations,
    batch_evaluate,
]

# Create the critic agent
critic = Agent(
    name="Adversarial Critic",
    instructions=CRITIC_PROMPT,
    description="""GPTLens-style adversarial critic that evaluates findings on 
    Correctness, Severity, and Profitability. Rejects findings scoring < 5 on 
    any dimension. The last line of defense against false positives.""",
    tools=critic_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('AEGIS_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = [
    'critic',
    'CriticScore',
    'CriticEvaluation',
    'Verdict',
    'evaluate_finding',
    'record_evaluation',
    'get_evaluation',
    'get_all_evaluations',
    'batch_evaluate',
]
