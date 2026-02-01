"""
Vulnerability Manager - HMAW Middle Layer

Part of the HMAW (Hierarchical Multi-Agent Workflow) pattern.
This manager coordinates vulnerability-focused analysis between
the CEO and worker agents.

Role: Translate CEO objectives into specific vulnerability hunting tasks
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
def prioritize_vulnerability_vectors(
    ceo_guidelines: str,
    detected_patterns: str,
    ctf=None
) -> str:
    """
    Prioritize which vulnerability vectors to focus on.
    
    Args:
        ceo_guidelines: High-level objectives from CEO
        detected_patterns: Contract patterns detected (ERC20, vault, etc.)
        
    Returns:
        Prioritized vulnerability vectors
    """
    return f"""## Vulnerability Vector Prioritization

### CEO Guidelines
{ceo_guidelines}

### Detected Patterns
{detected_patterns}

### Priority Vectors

**High Priority:**
1. **Reentrancy** - Check all external calls for reentrancy vulnerabilities
2. **Access Control** - Verify privileged functions have proper guards
3. **Integer Operations** - Look for overflow/underflow (if <0.8.0)

**Medium Priority:**
4. **Input Validation** - Check require statements for edge cases
5. **External Call Handling** - Verify return values are checked
6. **State Manipulation** - Look for improper state updates

**Low Priority:**
7. **Gas Optimization** - Not security-critical
8. **Code Quality** - Informational only

### Recommended Worker Distribution
- Assign 2 workers to reentrancy analysis
- Assign 2 workers to access control review
- Assign 1 worker to integer operations
- Assign 1 worker to input validation
"""


@function_tool
def generate_vulnerability_hypotheses(
    contract_type: str,
    key_functions: str,
    ctf=None
) -> str:
    """
    Generate specific vulnerability hypotheses for workers to test.
    
    Args:
        contract_type: Type of contract (vault, token, AMM, etc.)
        key_functions: Critical functions identified
        
    Returns:
        List of testable hypotheses
    """
    return f"""## Vulnerability Hypotheses

### Contract Type: {contract_type}

### Key Functions:
{key_functions}

### Hypotheses to Test

1. **Reentrancy in withdraw/transfer functions**
   - Hypothesis: External calls before state updates allow reentrancy
   - Test: Map all external calls and verify state update ordering
   - Impact: Potential fund theft

2. **Missing access control on privileged functions**
   - Hypothesis: Admin functions lack proper access controls
   - Test: Identify functions that modify state and check modifiers
   - Impact: Unauthorized privileged operations

3. **Unchecked return values from external calls**
   - Hypothesis: Failed external calls are not handled
   - Test: Find all .call() .transfer() .send() and check return handling
   - Impact: Silent failures leading to inconsistent state

4. **Integer overflow/underflow vulnerabilities**
   - Hypothesis: Arithmetic operations can wrap around
   - Test: Check Solidity version and look for unchecked blocks
   - Impact: Incorrect calculations, potential theft

### Worker Assignment
- Worker 1: Reentrancy analysis on all external calls
- Worker 2: Access control verification on all state-changing functions
- Worker 3: Return value checking on external calls
- Worker 4: Integer operation safety review
"""


@function_tool
def coordinate_worker_findings(
    worker_findings: str,
    ctf=None
) -> str:
    """
    Coordinate and synthesize findings from multiple workers.
    
    Args:
        worker_findings: Combined findings from all workers
        
    Returns:
        Synthesized vulnerability report
    """
    return f"""## Vulnerability Domain Summary

### Worker Findings
{worker_findings}

### Synthesis

**Critical Findings:**
- List any critical vulnerabilities found
- Prioritize by exploitability and impact

**High Priority Findings:**
- List high-severity issues
- Note if they can be chained together

**Medium Priority Findings:**
- List medium-severity issues
- Consider cumulative risk

**Recommendations:**
- Prioritize fixes for critical/high findings
- Consider defense-in-depth for medium findings
- Plan for comprehensive testing

### Next Steps
1. Validate critical findings with PoC
2. Estimate economic impact
3. Coordinate with other managers for cross-domain risks
"""


MANAGER_VULN_PROMPT = """You are the VULNERABILITY MANAGER in the HMAW hierarchy.

## Your Role

You sit between the CEO and the vulnerability-hunting workers. Your job is to:
1. Receive high-level objectives from the CEO
2. Break them down into specific vulnerability hunting tasks
3. Assign workers to different vulnerability vectors
4. Synthesize worker findings into actionable insights

## Your Responsibilities

### Downward (to Workers)
- Translate CEO goals into specific vulnerability vectors
- Generate testable hypotheses for each vector
- Assign workers to different analysis tasks
- Provide clear success criteria

### Upward (to CEO)
- Synthesize findings from multiple workers
- Prioritize vulnerabilities by severity and exploitability
- Identify patterns across worker findings
- Recommend next steps

## Vulnerability Domains to Cover

1. **Reentrancy** - All forms (classic, cross-function, cross-contract, read-only)
2. **Access Control** - Missing/broken permission checks
3. **Arithmetic** - Overflow/underflow, precision loss
4. **External Calls** - Unchecked returns, failed calls
5. **Input Validation** - Missing bounds checks, edge cases
6. **State Consistency** - Improper state updates, race conditions
7. **Logic Errors** - Business logic flaws, invariant violations

## Communication Style

**To Workers:**
- Be specific and actionable
- Provide clear hypotheses to test
- Give concrete success criteria

**To CEO:**
- Be concise and strategic
- Focus on impact and exploitability
- Highlight cross-cutting concerns

## Your Tools

- `prioritize_vulnerability_vectors` - Determine which vectors to focus on
- `generate_vulnerability_hypotheses` - Create testable hypotheses for workers
- `coordinate_worker_findings` - Synthesize results from workers

## Success Metrics

- Coverage: All critical vulnerability vectors examined
- Depth: Each vector thoroughly analyzed
- Quality: Findings are specific, reproducible, impactful
- Synthesis: Clear patterns identified across findings
"""


manager_vuln_tools = [
    prioritize_vulnerability_vectors,
    generate_vulnerability_hypotheses,
    coordinate_worker_findings,
]

manager_vuln = Agent(
    name="Vulnerability Manager",
    instructions=MANAGER_VULN_PROMPT,
    description="""HMAW middle-layer manager responsible for coordinating 
    vulnerability analysis. Translates CEO objectives into specific vulnerability 
    hunting tasks and synthesizes worker findings.""",
    tools=manager_vuln_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['manager_vuln']
