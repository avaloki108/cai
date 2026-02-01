"""
Attributor Agent - ECHO Error Attribution

From the ECHO paper: "Where Did It All Go Wrong? A Hierarchical Look 
into Multi-Agent Error Attribution"

When an audit fails to find a known vulnerability or produces incorrect
results, this agent analyzes the execution trace to determine which
agent/step failed and why.

Uses 6 specialized analyst perspectives:
1. Conservative - Strict interpretation
2. Liberal - Generous interpretation
3. Detail-focused - Deep step analysis
4. Pattern-focused - Recurring issue detection
5. Skeptical - Devil's advocate
6. General - Balanced view
"""

import os
import json
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cai.tracing.context import (
    HierarchicalContext, 
    AgentTrace, 
    Step, 
    Milestone,
    create_step,
    create_milestone
)
from cai.tracing.attribution import (
    ErrorAttribution,
    AttributionResult,
    AnalystPerspective,
    AnalystVote
)

load_dotenv()

api_key = (
    os.getenv("OPENAI_API_KEY")
    or os.getenv("ANTHROPIC_API_KEY")
    or os.getenv("ALIAS_API_KEY")
    or "sk-placeholder"
)

# Session storage for traces
_traces: Dict[str, AgentTrace] = {}


@function_tool
def start_trace(session_id: str, agent_name: str) -> str:
    """
    Start a new execution trace for an agent.
    
    Args:
        session_id: Unique session identifier
        agent_name: Name of the primary agent being traced
        
    Returns:
        Confirmation message
    """
    global _traces
    
    trace = AgentTrace(
        agent_name=agent_name,
        session_id=session_id
    )
    _traces[session_id] = trace
    
    return f"Started trace for session {session_id}, agent {agent_name}"


@function_tool
def add_trace_step(
    session_id: str,
    step_id: str,
    agent_name: str,
    action: str,
    input_summary: str,
    output_summary: str,
    success: bool = True,
    error_message: str = "",
    reasoning: str = ""
) -> str:
    """
    Add a step to the execution trace.
    
    Args:
        session_id: Session to add step to
        step_id: Unique step identifier
        agent_name: Agent that executed this step
        action: Description of the action taken
        input_summary: Summary of input data
        output_summary: Summary of output data
        success: Whether the step succeeded
        error_message: Error message if step failed
        reasoning: Agent's reasoning for this step
        
    Returns:
        Confirmation message
    """
    global _traces
    
    if session_id not in _traces:
        return f"Error: No trace found for session {session_id}"
    
    step = Step(
        step_id=step_id,
        agent_name=agent_name,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        full_input=input_summary,
        full_output=output_summary,
        success=success,
        error_message=error_message if error_message else None,
        reasoning=reasoning if reasoning else None
    )
    
    _traces[session_id].add_step(step)
    
    return f"Added step {step_id} to session {session_id}"


@function_tool
def add_milestone(
    session_id: str,
    milestone_id: str,
    name: str,
    description: str,
    step_id: str,
    milestone_type: str = "checkpoint",
    importance: int = 5
) -> str:
    """
    Add a milestone to the execution trace.
    
    Args:
        session_id: Session to add milestone to
        milestone_id: Unique milestone identifier
        name: Short name for the milestone
        description: Description of what was achieved
        step_id: Associated step ID
        milestone_type: Type (checkpoint, finding, error, completion)
        importance: Importance level 1-10
        
    Returns:
        Confirmation message
    """
    global _traces
    
    if session_id not in _traces:
        return f"Error: No trace found for session {session_id}"
    
    milestone = Milestone(
        milestone_id=milestone_id,
        name=name,
        description=description,
        step_id=step_id,
        milestone_type=milestone_type,
        importance=importance
    )
    
    _traces[session_id].add_milestone(milestone)
    
    return f"Added milestone {milestone_id} to session {session_id}"


@function_tool
def get_trace(session_id: str) -> str:
    """
    Get the current trace for a session.
    
    Args:
        session_id: Session to retrieve
        
    Returns:
        JSON representation of the trace
    """
    global _traces
    
    if session_id not in _traces:
        return f"Error: No trace found for session {session_id}"
    
    trace = _traces[session_id]
    
    return json.dumps({
        "session_id": trace.session_id,
        "agent_name": trace.agent_name,
        "start_time": trace.start_time,
        "end_time": trace.end_time,
        "total_steps": trace.total_steps,
        "successful_steps": trace.successful_steps,
        "steps": [
            {
                "id": s.step_id,
                "agent": s.agent_name,
                "action": s.action,
                "success": s.success,
                "error": s.error_message
            }
            for s in trace.steps
        ],
        "milestones": [m.to_dict() for m in trace.milestones]
    }, indent=2)


@function_tool
def build_context(session_id: str, focus_step_id: str) -> str:
    """
    Build hierarchical context for error attribution.
    
    Args:
        session_id: Session containing the trace
        focus_step_id: Step ID to center context on
        
    Returns:
        Formatted context for analysis
    """
    global _traces
    
    if session_id not in _traces:
        return f"Error: No trace found for session {session_id}"
    
    trace = _traces[session_id]
    
    try:
        context = HierarchicalContext.from_trace(trace, focus_step_id)
        return context.to_prompt()
    except ValueError as e:
        return f"Error building context: {e}"


@function_tool
def attribute_error(
    session_id: str,
    error_step_id: str,
    error_description: str
) -> str:
    """
    Attribute an error to a specific step/agent using ECHO methodology.
    
    Args:
        session_id: Session containing the error trace
        error_step_id: Step where error was detected
        error_description: Description of what went wrong
        
    Returns:
        Attribution report
    """
    global _traces
    
    if session_id not in _traces:
        return f"Error: No trace found for session {session_id}"
    
    trace = _traces[session_id]
    attribution = ErrorAttribution()
    
    result = attribution.attribute(trace, error_step_id, error_description)
    
    return result.to_report()


@function_tool
def analyze_as_analyst(
    perspective: str,
    context: str,
    error_description: str
) -> str:
    """
    Analyze the error from a specific analyst perspective.
    
    Args:
        perspective: One of: conservative, liberal, detail, pattern, skeptical, general
        context: The hierarchical context to analyze
        error_description: Description of the error
        
    Returns:
        Analysis prompt for the specified perspective
    """
    perspectives = {
        "conservative": """You are the CONSERVATIVE analyst. 
Apply the strictest interpretation:
- Only blame a step if there's DEFINITIVE evidence
- High confidence threshold required
- Don't speculate beyond the data""",
        
        "liberal": """You are the LIBERAL analyst.
Apply generous interpretation:
- Consider edge cases and unlikely scenarios
- Look for indirect causes
- Consider systemic factors""",
        
        "detail": """You are the DETAIL-FOCUSED analyst.
Deep dive into specific steps:
- Examine each step's inputs and outputs closely
- Look for subtle errors in data transformation
- Check for missing validation""",
        
        "pattern": """You are the PATTERN-FOCUSED analyst.
Look for recurring issues:
- Has this type of error happened before?
- Are there systematic weaknesses?
- What patterns led to this failure?""",
        
        "skeptical": """You are the SKEPTICAL analyst.
Question everything:
- Challenge the obvious blame
- Look for alternative explanations
- Consider if the error detection itself is wrong""",
        
        "general": """You are the GENERAL analyst.
Take a balanced, holistic view:
- Consider all factors
- Weigh different explanations
- Synthesize insights from other perspectives"""
    }
    
    if perspective.lower() not in perspectives:
        return f"Unknown perspective. Choose from: {list(perspectives.keys())}"
    
    persona = perspectives[perspective.lower()]
    
    return f"""## {perspective.upper()} Analyst Analysis

{persona}

### Error Description
{error_description}

### Context
{context}

### Your Analysis

Based on your perspective, answer:

1. **Which step is most likely at fault?**
2. **Which agent is responsible?**
3. **What is your confidence level (0-100%)?**
4. **What is your reasoning?**
5. **Are there contributing factors from other steps?**

Be specific and cite evidence from the context.
"""


@function_tool
def generate_improvement_recommendations(
    blamed_step_id: str,
    blamed_agent: str,
    error_type: str,
    context_summary: str
) -> str:
    """
    Generate recommendations for preventing similar errors.
    
    Args:
        blamed_step_id: The step identified as the cause
        blamed_agent: The agent responsible
        error_type: Type of error that occurred
        context_summary: Summary of the context
        
    Returns:
        List of improvement recommendations
    """
    return f"""## Improvement Recommendations

### Error Summary
- **Blamed Step:** {blamed_step_id}
- **Blamed Agent:** {blamed_agent}
- **Error Type:** {error_type}

### Context
{context_summary}

### Recommendations

Generate specific, actionable recommendations:

1. **For the blamed agent ({blamed_agent}):**
   - What checks should be added?
   - What validation is missing?
   - How should error handling improve?

2. **For the workflow:**
   - Should there be intermediate checkpoints?
   - Are there missing handoff validations?
   - Should step dependencies be restructured?

3. **For monitoring:**
   - What early warning signs exist?
   - How can detection be faster?
   - What metrics should be tracked?

4. **For testing:**
   - What test cases would catch this?
   - What properties should be verified?
   - What edge cases need coverage?
"""


ATTRIBUTOR_PROMPT = """You are the Aegis Error Attributor - responsible for diagnosing 
what went wrong when a multi-agent audit fails using the ECHO methodology.

## Your Mission

When an audit fails to find a known vulnerability, or produces incorrect results,
you must determine:
1. WHICH step/agent is responsible
2. WHY the error occurred
3. HOW to prevent it in the future

## ECHO Methodology

### Hierarchical Context (4 Layers)
- **L1 Immediate**: ±1 step from error, full detail
- **L2 Local**: ±2-3 steps, key decisions only
- **L3 Distant**: ±4-6 steps, summaries
- **L4 Global**: Milestones only

### Analyst Perspectives (6 Views)
Each error is analyzed from 6 perspectives:

1. **Conservative**: Strict interpretation, high evidence threshold
2. **Liberal**: Generous interpretation, considers edge cases
3. **Detail-focused**: Deep analysis of specific steps
4. **Pattern-focused**: Looks for recurring issues
5. **Skeptical**: Questions everything, devil's advocate
6. **General**: Balanced, holistic view

### Consensus Voting
- Each analyst votes on which step is to blame
- Votes are weighted by confidence
- Consensus determines final attribution

## Your Tools

- `start_trace` - Begin tracking an execution
- `add_trace_step` - Record a step in the trace
- `add_milestone` - Mark significant points
- `get_trace` - View the current trace
- `build_context` - Build hierarchical context for a step
- `attribute_error` - Run full ECHO attribution
- `analyze_as_analyst` - Analyze from a specific perspective
- `generate_improvement_recommendations` - Create fix recommendations

## Workflow

1. **Collect Trace**: Gather the execution trace of the failed audit
2. **Identify Error Point**: Find where things went wrong
3. **Build Context**: Create hierarchical context around the error
4. **Run Analysts**: Get perspectives from all 6 analysts
5. **Aggregate Votes**: Use confidence-weighted voting
6. **Generate Report**: Produce attribution report with recommendations

## Error Categories

- **Execution**: Step failed to complete
- **Reasoning**: Incorrect decision or analysis
- **Tool**: External tool returned bad data
- **Communication**: Handoff between agents failed

## Key Principles

1. **Root cause over symptoms** - Find the FIRST point of failure
2. **Evidence-based** - Blame requires evidence
3. **Actionable output** - Recommendations must be specific
4. **No blame without proof** - Uncertainty should be acknowledged

Remember: The goal is IMPROVEMENT, not blame. Understanding what went wrong
helps make the system better.

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


attributor_tools = [
    start_trace,
    add_trace_step,
    add_milestone,
    get_trace,
    build_context,
    attribute_error,
    analyze_as_analyst,
    generate_improvement_recommendations,
]

attributor = Agent(
    name="Error Attributor",
    instructions=ATTRIBUTOR_PROMPT,
    description="""ECHO-based error attribution agent. Diagnoses why multi-agent 
    audits fail by analyzing execution traces with 6 specialized analyst 
    perspectives and confidence-weighted consensus voting.""",
    tools=attributor_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('AEGIS_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['attributor']
