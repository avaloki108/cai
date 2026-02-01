"""
Audit Planner Agent - Pre-Act Multi-Step Planning

From the Pre-Act research paper: "Pre-Act: Multi-Step Planning and Reasoning 
Improves Acting in LLM Agents"

Key insights:
- Generate a comprehensive multi-step plan BEFORE executing actions
- Each step specifies: action, agent, reasoning, expected output
- Plan is refined iteratively as tool outputs come in
- 70% improvement in Action Recall on benchmarks
- Fine-tuned 70B model outperforms GPT-4 by 69.5%

This agent generates execution plans that coordinate other Aegis agents,
ensuring systematic coverage and adaptive refinement during audits.
"""

import os
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
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


class StepStatus(Enum):
    """Status of a plan step."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlanStep:
    """A single step in the audit plan."""
    
    step_number: int
    action: str
    agent: str
    reasoning: str
    expected_output: str
    depends_on: List[int] = field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    actual_output: Optional[str] = None
    observations: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_number,
            "action": self.action,
            "agent": self.agent,
            "reasoning": self.reasoning,
            "expected_output": self.expected_output,
            "depends_on": self.depends_on,
            "status": self.status.value,
            "actual_output": self.actual_output,
            "observations": self.observations
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PlanStep':
        return cls(
            step_number=data.get("step", data.get("step_number", 0)),
            action=data.get("action", ""),
            agent=data.get("agent", ""),
            reasoning=data.get("reasoning", ""),
            expected_output=data.get("expected_output", ""),
            depends_on=data.get("depends_on", []),
            status=StepStatus(data.get("status", "pending")),
            actual_output=data.get("actual_output"),
            observations=data.get("observations")
        )


@dataclass  
class AuditPlan:
    """Complete audit execution plan."""
    
    goal: str
    target: str
    steps: List[PlanStep] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    current_step: int = 0
    
    def add_step(self, step: PlanStep) -> None:
        """Add a step to the plan."""
        self.steps.append(step)
        self.last_updated = datetime.now().isoformat()
    
    def get_next_step(self) -> Optional[PlanStep]:
        """Get the next pending step."""
        for step in self.steps:
            if step.status == StepStatus.PENDING:
                # Check dependencies
                deps_satisfied = all(
                    self.steps[d-1].status == StepStatus.COMPLETED
                    for d in step.depends_on
                    if d <= len(self.steps)
                )
                if deps_satisfied:
                    return step
        return None
    
    def update_step(
        self, 
        step_number: int, 
        status: StepStatus,
        actual_output: Optional[str] = None,
        observations: Optional[str] = None
    ) -> None:
        """Update a step's status and output."""
        if 0 < step_number <= len(self.steps):
            step = self.steps[step_number - 1]
            step.status = status
            if actual_output:
                step.actual_output = actual_output
            if observations:
                step.observations = observations
            self.last_updated = datetime.now().isoformat()
    
    def get_completed_context(self) -> str:
        """Get summary of completed steps for context."""
        completed = []
        for step in self.steps:
            if step.status == StepStatus.COMPLETED:
                completed.append(
                    f"Step {step.step_number} ({step.action}): {step.observations or 'Completed'}"
                )
        return "\n".join(completed) if completed else "No steps completed yet."
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "target": self.target,
            "steps": [s.to_dict() for s in self.steps],
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "current_step": self.current_step,
            "progress": {
                "total": len(self.steps),
                "completed": sum(1 for s in self.steps if s.status == StepStatus.COMPLETED),
                "pending": sum(1 for s in self.steps if s.status == StepStatus.PENDING),
                "failed": sum(1 for s in self.steps if s.status == StepStatus.FAILED)
            }
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# Global plan storage for current session
_current_plan: Optional[AuditPlan] = None


@function_tool
def create_audit_plan(
    target: str,
    goal: str,
    steps: str
) -> str:
    """
    Create a new audit execution plan.
    
    Args:
        target: The contract path or address to audit
        goal: High-level goal of the audit (e.g., "Find exploitable vulnerabilities")
        steps: JSON array of steps, each with: action, agent, reasoning, expected_output, depends_on
        
    Returns:
        JSON representation of the created plan
    """
    global _current_plan
    
    try:
        steps_data = json.loads(steps)
    except json.JSONDecodeError as e:
        return f"Error parsing steps JSON: {e}"
    
    plan = AuditPlan(goal=goal, target=target)
    
    for i, step_data in enumerate(steps_data):
        step = PlanStep(
            step_number=i + 1,
            action=step_data.get("action", f"Step {i+1}"),
            agent=step_data.get("agent", "web3_auditor"),
            reasoning=step_data.get("reasoning", ""),
            expected_output=step_data.get("expected_output", ""),
            depends_on=step_data.get("depends_on", [])
        )
        plan.add_step(step)
    
    _current_plan = plan
    return plan.to_json()


@function_tool
def get_current_plan() -> str:
    """
    Get the current audit plan.
    
    Returns:
        JSON representation of current plan, or message if no plan exists
    """
    global _current_plan
    
    if _current_plan is None:
        return "No plan exists. Create one with create_audit_plan."
    
    return _current_plan.to_json()


@function_tool
def get_next_step() -> str:
    """
    Get the next step to execute from the current plan.
    
    Returns:
        JSON representation of next step, or message if no steps remain
    """
    global _current_plan
    
    if _current_plan is None:
        return "No plan exists. Create one with create_audit_plan."
    
    next_step = _current_plan.get_next_step()
    
    if next_step is None:
        return "All steps completed or no steps available (check dependencies)."
    
    return json.dumps(next_step.to_dict(), indent=2)


@function_tool
def update_step_status(
    step_number: int,
    status: str,
    actual_output: str = "",
    observations: str = ""
) -> str:
    """
    Update the status of a plan step after execution.
    
    Args:
        step_number: The step number to update (1-indexed)
        status: New status: pending, in_progress, completed, failed, skipped
        actual_output: What the step actually produced
        observations: Key observations that may inform future steps
        
    Returns:
        Updated step information
    """
    global _current_plan
    
    if _current_plan is None:
        return "No plan exists. Create one with create_audit_plan."
    
    try:
        step_status = StepStatus(status.lower())
    except ValueError:
        valid = [s.value for s in StepStatus]
        return f"Invalid status '{status}'. Valid values: {valid}"
    
    _current_plan.update_step(
        step_number=step_number,
        status=step_status,
        actual_output=actual_output if actual_output else None,
        observations=observations if observations else None
    )
    
    if step_number <= len(_current_plan.steps):
        return json.dumps(_current_plan.steps[step_number - 1].to_dict(), indent=2)
    return f"Step {step_number} not found in plan."


@function_tool
def add_step_to_plan(
    action: str,
    agent: str,
    reasoning: str,
    expected_output: str,
    depends_on: str = "[]",
    insert_after: int = -1
) -> str:
    """
    Add a new step to the current plan (adaptive refinement).
    
    Args:
        action: What action to perform
        agent: Which agent should perform it
        reasoning: Why this step is needed
        expected_output: What we expect to get
        depends_on: JSON array of step numbers this depends on
        insert_after: Step number to insert after (-1 = append to end)
        
    Returns:
        Updated plan with new step
    """
    global _current_plan
    
    if _current_plan is None:
        return "No plan exists. Create one with create_audit_plan."
    
    try:
        deps = json.loads(depends_on)
    except json.JSONDecodeError:
        deps = []
    
    new_step_num = len(_current_plan.steps) + 1
    
    new_step = PlanStep(
        step_number=new_step_num,
        action=action,
        agent=agent,
        reasoning=reasoning,
        expected_output=expected_output,
        depends_on=deps
    )
    
    if insert_after == -1 or insert_after >= len(_current_plan.steps):
        _current_plan.add_step(new_step)
    else:
        # Insert and renumber
        _current_plan.steps.insert(insert_after, new_step)
        for i, step in enumerate(_current_plan.steps):
            step.step_number = i + 1
    
    return _current_plan.to_json()


@function_tool
def remove_step_from_plan(step_number: int, reason: str = "") -> str:
    """
    Remove a step from the plan (adaptive refinement).
    
    Args:
        step_number: Step to remove
        reason: Why this step is being removed
        
    Returns:
        Updated plan without the step
    """
    global _current_plan
    
    if _current_plan is None:
        return "No plan exists."
    
    if step_number < 1 or step_number > len(_current_plan.steps):
        return f"Invalid step number {step_number}."
    
    removed = _current_plan.steps.pop(step_number - 1)
    
    # Renumber remaining steps
    for i, step in enumerate(_current_plan.steps):
        step.step_number = i + 1
        # Update dependencies
        step.depends_on = [d - 1 if d > step_number else d for d in step.depends_on if d != step_number]
    
    return f"Removed step: {removed.action}. Reason: {reason}\n\n{_current_plan.to_json()}"


@function_tool  
def get_plan_summary() -> str:
    """
    Get a summary of plan progress and key findings so far.
    
    Returns:
        Summary of completed steps and accumulated context
    """
    global _current_plan
    
    if _current_plan is None:
        return "No plan exists."
    
    summary = f"""## Audit Plan Summary

**Target:** {_current_plan.target}
**Goal:** {_current_plan.goal}

### Progress
- Total Steps: {len(_current_plan.steps)}
- Completed: {sum(1 for s in _current_plan.steps if s.status == StepStatus.COMPLETED)}
- Pending: {sum(1 for s in _current_plan.steps if s.status == StepStatus.PENDING)}
- Failed: {sum(1 for s in _current_plan.steps if s.status == StepStatus.FAILED)}

### Completed Steps Context
{_current_plan.get_completed_context()}

### Upcoming Steps
"""
    
    pending = [s for s in _current_plan.steps if s.status == StepStatus.PENDING][:3]
    for step in pending:
        summary += f"\n{step.step_number}. {step.action} (via {step.agent})"
    
    return summary


# Planner system prompt
PLANNER_PROMPT = """You are the Aegis Audit Planner - responsible for creating and managing 
execution plans for security audits using the Pre-Act methodology.

## Pre-Act Principles

Before ANY action, generate a structured multi-step plan. The plan should:

1. **Decompose** the audit goal into concrete, achievable steps
2. **Specify** which agent/tool is best for each step  
3. **Reason** about why each step is needed
4. **Anticipate** what output each step should produce
5. **Track dependencies** between steps

## Available Agents

- `static_analyzer` - Slither-based pattern detection (fast, broad coverage)
- `exploit_hunter` - Mythril symbolic execution (deep, proves exploitability)
- `fuzzing_specialist` - Echidna/Medusa campaigns (property testing, edge cases)
- `web3_auditor` - Primary auditor (comprehensive, all tools)

## Plan Structure

Each step should have:
```json
{
  "action": "What to do (e.g., 'static_analysis', 'deep_analysis')",
  "agent": "Which agent to use",
  "reasoning": "Why this step is needed",
  "expected_output": "What we expect to learn",
  "depends_on": [step_numbers]
}
```

## Adaptive Refinement

After each step completes:
1. Review the actual output vs expected
2. If findings warrant deeper investigation, ADD new steps
3. If a path is unproductive, SKIP remaining steps in that direction
4. Update the plan based on observations

## Example Plan for Contract Audit

```json
[
  {
    "action": "index_project",
    "agent": "web3_auditor",
    "reasoning": "Map structure and index code for later search",
    "expected_output": "Project map + RAG index",
    "depends_on": []
  },
  {
    "action": "slither_scan",
    "agent": "static_analyzer",
    "reasoning": "Fast static analysis coverage",
    "expected_output": "Slither findings JSON",
    "depends_on": [1]
  },
  {
    "action": "triage_slither",
    "agent": "web3_auditor",
    "reasoning": "Filter static analysis noise early",
    "expected_output": "Triage output with filtered findings",
    "depends_on": [2]
  },
  {
    "action": "medusa_scan",
    "agent": "fuzzing_specialist",
    "reasoning": "Coverage-guided fuzzing",
    "expected_output": "Medusa findings JSON",
    "depends_on": [1]
  },
  {
    "action": "triage_medusa",
    "agent": "web3_auditor",
    "reasoning": "Filter reachability/feasibility",
    "expected_output": "Triage output with filtered findings",
    "depends_on": [4]
  },
  {
    "action": "mythril_scan",
    "agent": "exploit_hunter",
    "reasoning": "Symbolic execution for exploit paths",
    "expected_output": "Mythril findings JSON",
    "depends_on": [1]
  },
  {
    "action": "triage_mythril",
    "agent": "web3_auditor",
    "reasoning": "Filter unreachable/benign paths",
    "expected_output": "Triage output with filtered findings",
    "depends_on": [6]
  },
  {
    "action": "forge_fuzz",
    "agent": "web3_auditor",
    "reasoning": "Project-specific fuzzing with Forge",
    "expected_output": "Forge fuzz output",
    "depends_on": [1]
  },
  {
    "action": "triage_forge",
    "agent": "web3_auditor",
    "reasoning": "Discard non-reproducible failures",
    "expected_output": "Triage output with filtered findings",
    "depends_on": [8]
  },
  {
    "action": "echidna_scribble",
    "agent": "fuzzing_specialist",
    "reasoning": "Invariant validation",
    "expected_output": "Echidna/Scribble findings JSON",
    "depends_on": [1]
  },
  {
    "action": "triage_echidna",
    "agent": "web3_auditor",
    "reasoning": "Filter invalid invariants",
    "expected_output": "Triage output with filtered findings",
    "depends_on": [10]
  },
  {
    "action": "certora_gambit_optional",
    "agent": "web3_auditor",
    "reasoning": "Formal + simulation checks when available",
    "expected_output": "Certora/Gambit findings JSON",
    "depends_on": [1]
  },
  {
    "action": "triage_certora_gambit",
    "agent": "web3_auditor",
    "reasoning": "Filter vacuous/low-PnL findings",
    "expected_output": "Triage output with filtered findings",
    "depends_on": [12]
  },
  {
    "action": "council_review",
    "agent": "web3_auditor",
    "reasoning": "Cross-tool consolidation and confidence scoring",
    "expected_output": "Council-labeled findings",
    "depends_on": [3, 5, 7, 9, 11, 13]
  },
  {
    "action": "report_generation",
    "agent": "web3_auditor",
    "reasoning": "Produce final report + manual test plan",
    "expected_output": "Final report draft",
    "depends_on": [14]
  },
  {
    "action": "fix_verification",
    "agent": "web3_auditor",
    "reasoning": "Re-run affected tools on diffs",
    "expected_output": "Fix verification status",
    "depends_on": [15]
  }
]
```

## Your Tools

- `create_audit_plan` - Create a new plan for an audit target
- `get_current_plan` - View the current plan state
- `get_next_step` - Get the next step to execute
- `update_step_status` - Mark a step as completed/failed with observations
- `add_step_to_plan` - Add new steps based on findings (adaptive refinement)
- `remove_step_from_plan` - Remove unneeded steps
- `get_plan_summary` - Get progress summary

## Key Principles

1. **Plan First** - Always create a plan before executing
2. **Be Specific** - Vague steps produce vague results
3. **Adapt** - Update the plan as you learn
4. **Track Context** - Use observations to inform future steps
5. **Stay Focused** - Don't chase every finding, prioritize by impact

Start by understanding the target, then create a comprehensive plan.

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


# Planning tools
planning_tools = [
    create_audit_plan,
    get_current_plan,
    get_next_step,
    update_step_status,
    add_step_to_plan,
    remove_step_from_plan,
    get_plan_summary,
]

# Create the planner agent
planner = Agent(
    name="Audit Planner",
    instructions=PLANNER_PROMPT,
    description="""Pre-Act planning agent that creates and manages multi-step audit 
    execution plans. Coordinates agent delegation and tracks progress through 
    adaptive refinement based on observations.""",
    tools=planning_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('AEGIS_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = [
    'planner',
    'AuditPlan',
    'PlanStep', 
    'StepStatus',
    'create_audit_plan',
    'get_current_plan',
    'get_next_step',
    'update_step_status',
    'add_step_to_plan',
    'remove_step_from_plan',
    'get_plan_summary',
]
