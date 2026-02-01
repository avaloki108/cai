"""
Access Control Manager - HMAW Middle Layer

Part of the HMAW (Hierarchical Multi-Agent Workflow) pattern.
This manager coordinates access control analysis between the CEO and worker agents.

Role: Translate CEO objectives into specific access control verification tasks
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
def prioritize_access_vectors(
    ceo_guidelines: str,
    privileged_functions: str,
    role_system: str = "unknown",
    ctf=None
) -> str:
    """
    Prioritize which access control vectors to verify.
    
    Args:
        ceo_guidelines: High-level objectives from CEO
        privileged_functions: List of privileged/admin functions
        role_system: Type of access control (owner, RBAC, multi-sig, etc.)
        
    Returns:
        Prioritized access control verification tasks
    """
    return f"""## Access Control Vector Prioritization

### CEO Guidelines
{ceo_guidelines}

### Privileged Functions:
{privileged_functions}

### Role System: {role_system}

### Priority Vectors

**Critical Priority:**
1. **Admin Function Access** - Verify all admin functions have proper guards
2. **Ownership Transfer** - Check ownership change mechanisms are secure
3. **Upgrade Controls** - Validate proxy upgrade permissions

**High Priority:**
4. **Role Management** - Verify role assignment/revocation is protected
5. **Permission Escalation** - Check for privilege escalation paths
6. **Multi-Sig Bypass** - Verify multi-sig cannot be bypassed

**Medium Priority:**
7. **Initialization** - Check initialize() can only be called once
8. **Delegatecall Access** - Verify delegatecall permissions
9. **Emergency Functions** - Check pause/unpause are protected

**Low Priority:**
10. **View Function Access** - Informational access restrictions
11. **Event Emission** - Access to emit certain events

### Recommended Worker Distribution
- Assign 2 workers to admin function verification
- Assign 1 worker to ownership/role management
- Assign 1 worker to upgrade/proxy controls
- Assign 1 worker to initialization and emergency functions
"""


@function_tool
def generate_access_hypotheses(
    role_system: str,
    privileged_functions: str,
    upgrade_pattern: str = "none",
    ctf=None
) -> str:
    """
    Generate specific access control hypotheses for workers to test.
    
    Args:
        role_system: Type of access control system
        privileged_functions: List of privileged functions
        upgrade_pattern: Upgrade pattern if applicable (UUPS, Transparent, etc.)
        
    Returns:
        List of testable access control hypotheses
    """
    return f"""## Access Control Hypotheses

### Role System: {role_system}
### Upgrade Pattern: {upgrade_pattern}

### Privileged Functions:
{privileged_functions}

### Hypotheses to Test

1. **Missing Access Control on Admin Functions**
   - Hypothesis: Critical functions lack proper access restrictions
   - Test: Map all state-changing functions and verify modifiers
   - Impact: Unauthorized privileged operations
   - Check: onlyOwner, onlyRole, or custom guards
   - Success: All admin functions have proper guards

2. **Ownership Transfer Vulnerabilities**
   - Hypothesis: Ownership can be transferred maliciously
   - Test: Review transferOwnership() and renounceOwnership()
   - Impact: Complete protocol takeover
   - Check: Two-step transfer, timelock, multi-sig requirement
   - Success: Ownership changes are properly protected

3. **Proxy Upgrade Access**
   - Hypothesis: Implementation can be upgraded by unauthorized party
   - Test: Verify upgradeTo() and upgradeToAndCall() permissions
   - Impact: Complete code replacement
   - Check: Admin role, timelock, multi-sig
   - Success: Only authorized parties can upgrade

4. **Role Escalation Paths**
   - Hypothesis: Users can escalate their own permissions
   - Test: Map all role assignment functions and check guards
   - Impact: Privilege escalation
   - Check: Only admin can grant roles, no self-assignment
   - Success: No paths to self-escalate privileges

5. **Initialization Replay**
   - Hypothesis: Initialize function can be called multiple times
   - Test: Check initializer modifier and storage slot
   - Impact: Re-initialization attack
   - Check: initializer modifier, initialized flag
   - Success: Initialize only callable once

6. **Delegatecall Abuse**
   - Hypothesis: Delegatecall can be used by unauthorized parties
   - Test: Find all delegatecall usage and check permissions
   - Impact: Arbitrary code execution in contract context
   - Check: Restricted to admin, whitelist, or specific addresses
   - Success: Delegatecall properly restricted

### Worker Assignment
- Worker 1: Admin function access verification
- Worker 2: Ownership and role management security
- Worker 3: Upgrade mechanism analysis (if applicable)
- Worker 4: Initialization and delegatecall checks
- Worker 5: Permission escalation path analysis
"""


@function_tool
def coordinate_access_findings(
    worker_findings: str,
    ctf=None
) -> str:
    """
    Coordinate and synthesize access control findings from multiple workers.
    
    Args:
        worker_findings: Combined findings from all workers
        
    Returns:
        Synthesized access control report
    """
    return f"""## Access Control Domain Summary

### Worker Findings
{worker_findings}

### Synthesis

**Critical Access Control Issues:**
- Missing access controls on admin functions
- Unprotected ownership transfers
- Insecure upgrade mechanisms
- Rank by exploitability and impact

**High Priority Issues:**
- Role escalation paths
- Multi-sig bypass opportunities
- Initialization vulnerabilities
- Note attack paths and preconditions

**Medium Priority Issues:**
- Weak access controls (not missing, but weak)
- Inconsistent permission patterns
- Missing event emissions for critical actions

### Access Control Matrix

| Function | Current Guard | Required | Status | Risk |
|----------|---------------|----------|--------|------|
| transferOwnership | onlyOwner | onlyOwner + 2-step | ⚠️ | HIGH |
| upgradeTo | onlyOwner | onlyOwner + timelock | ⚠️ | HIGH |
| grantRole | DEFAULT_ADMIN | DEFAULT_ADMIN | ✓ | OK |
| ... | ... | ... | ... | ... |

### Attack Paths

1. **Ownership Takeover**
   - Entry: Unprotected transferOwnership()
   - Impact: Complete protocol control
   - Mitigation: Implement 2-step transfer

2. **Upgrade Manipulation**
   - Entry: Unprotected upgradeTo()
   - Impact: Arbitrary code execution
   - Mitigation: Add timelock + multi-sig

### Recommendations

**Immediate Actions:**
1. Add access controls to all unprotected admin functions
2. Implement 2-step ownership transfer
3. Add timelock to upgrade mechanism

**Best Practices:**
- Use OpenZeppelin AccessControl for RBAC
- Implement 2-step ownership transfer
- Add timelocks to critical operations
- Use multi-sig for high-value decisions
- Emit events for all access control changes
- Document all roles and permissions

**Defense in Depth:**
- Layer multiple controls on critical functions
- Separate roles for different operations
- Time-delay sensitive operations
- Multi-party approval for irreversible actions
"""


MANAGER_ACCESS_PROMPT = """You are the ACCESS CONTROL MANAGER in the HMAW hierarchy.

## Your Role

You sit between the CEO and the access control verification workers. Your job is to:
1. Receive high-level objectives from the CEO
2. Break them down into specific access control verification tasks
3. Assign workers to different permission analysis areas
4. Synthesize worker findings into actionable security recommendations

## Your Responsibilities

### Downward (to Workers)
- Translate CEO goals into access control verification tasks
- Generate testable hypotheses for permission issues
- Assign workers to different control mechanisms
- Provide clear verification criteria

### Upward (to CEO)
- Synthesize findings into access control matrix
- Identify critical permission issues
- Map attack paths through access control flaws
- Recommend layered defense strategies

## Access Control Domains to Cover

1. **Admin Functions** - Owner-only, admin-only operations
2. **Ownership** - Transfer, renounce, two-step transfer
3. **Role Management** - Grant, revoke, renounce roles (RBAC)
4. **Upgrade Controls** - UUPS, Transparent proxy, implementation changes
5. **Initialization** - Constructor, initializer, setup functions
6. **Delegatecall** - Library usage, arbitrary code execution
7. **Emergency Functions** - Pause, unpause, emergency withdraw
8. **Multi-Sig** - Threshold signatures, timelock delays

## Access Control Principles

1. **Least Privilege** - Minimum necessary permissions
2. **Separation of Duties** - Different roles for different operations
3. **Defense in Depth** - Multiple layers of control
4. **Two-Person Rule** - Critical operations require multiple approvals
5. **Time Delays** - Timelocks on sensitive operations
6. **Auditability** - Events for all permission changes

## Verification Checklist

For each privileged function:
- [ ] Has explicit access control (modifier or require)
- [ ] Access control is sufficient for function's power
- [ ] Multiple controls for highly privileged operations
- [ ] Events emitted for state changes
- [ ] No way to bypass the access control
- [ ] Cannot be called during initialization to skip guards

## Communication Style

**To Workers:**
- Be specific about which functions to verify
- Provide clear access control requirements
- Request concrete attack paths if issues found

**To CEO:**
- Lead with critical missing controls
- Provide access control matrix for overview
- Highlight attack paths and mitigations
- Recommend defense-in-depth strategies

## Your Tools

- `prioritize_access_vectors` - Determine which controls to verify
- `generate_access_hypotheses` - Create testable permission hypotheses
- `coordinate_access_findings` - Synthesize results into security recommendations

## Success Metrics

- Coverage: All privileged functions verified
- Depth: Access controls evaluated for strength, not just presence
- Attack Paths: Clear mapping of permission-based attack vectors
- Recommendations: Actionable mitigation strategies
"""


manager_access_tools = [
    prioritize_access_vectors,
    generate_access_hypotheses,
    coordinate_access_findings,
]

manager_access = Agent(
    name="Access Control Manager",
    instructions=MANAGER_ACCESS_PROMPT,
    description="""HMAW middle-layer manager responsible for coordinating 
    access control analysis. Translates CEO objectives into specific permission 
    verification tasks and synthesizes findings into security recommendations.""",
    tools=manager_access_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['manager_access']
