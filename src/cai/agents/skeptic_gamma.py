"""
Skeptic Gamma - The Unyielding Defense Analyst

Part of the adversarial review layer. Skeptic Gamma specializes in
exposing DEFENSIVE mechanisms that block exploitation.

Role: Obliterate vulnerability claims by revealing protective controls.

Tactics:
- Find access control guards
- Identify input validation
- Expose reentrancy guards
- Discover rate limiting
- Reveal emergency stops
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
def find_access_controls(
    function_name: str,
    contract_code: str,
    claimed_bypass: str = "",
    ctf=None
) -> str:
    """
    Find access control mechanisms protecting a function.
    
    Args:
        function_name: Name of the function to analyze
        contract_code: Contract source code
        claimed_bypass: Claimed method to bypass controls
        
    Returns:
        Access control analysis
    """
    try:
        controls_found = []
        
        # Check for common access control patterns
        if "onlyOwner" in contract_code or "require(msg.sender == owner" in contract_code:
            controls_found.append({
                "type": "owner_check",
                "mechanism": "onlyOwner modifier or explicit owner check",
                "strength": "STRONG",
                "bypass_difficulty": "HIGH"
            })
        
        if "onlyRole" in contract_code or "hasRole" in contract_code:
            controls_found.append({
                "type": "role_based_access",
                "mechanism": "Role-based access control (AccessControl)",
                "strength": "STRONG",
                "bypass_difficulty": "HIGH"
            })
        
        if "whitelist" in contract_code.lower() or "allowlist" in contract_code.lower():
            controls_found.append({
                "type": "whitelist",
                "mechanism": "Whitelist/allowlist check",
                "strength": "MEDIUM",
                "bypass_difficulty": "MEDIUM"
            })
        
        result = {
            "function": function_name,
            "controls_found": len(controls_found),
            "control_details": controls_found,
            "claimed_bypass": claimed_bypass,
            "verdict": "PROTECTED" if controls_found else "UNPROTECTED",
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error finding access controls: {str(e)}"})


@function_tool
def find_input_validation(
    function_name: str,
    contract_code: str,
    claimed_malicious_input: str = "",
    ctf=None
) -> str:
    """
    Find input validation mechanisms.
    
    Args:
        function_name: Name of the function to analyze
        contract_code: Contract source code
        claimed_malicious_input: Claimed malicious input
        
    Returns:
        Input validation analysis
    """
    try:
        validations_found = []
        
        # Check for validation patterns
        if "require(" in contract_code:
            validations_found.append({
                "type": "require_checks",
                "mechanism": "require() statements for validation",
                "protects_against": "Invalid inputs, edge cases"
            })
        
        if "> 0" in contract_code or "!= 0" in contract_code:
            validations_found.append({
                "type": "zero_check",
                "mechanism": "Zero value validation",
                "protects_against": "Zero amounts, division by zero"
            })
        
        if "length" in contract_code and "require" in contract_code:
            validations_found.append({
                "type": "length_check",
                "mechanism": "Array/string length validation",
                "protects_against": "Empty inputs, overflow"
            })
        
        result = {
            "function": function_name,
            "validations_found": len(validations_found),
            "validation_details": validations_found,
            "claimed_malicious_input": claimed_malicious_input,
            "verdict": "VALIDATED" if validations_found else "UNVALIDATED",
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error finding input validation: {str(e)}"})


@function_tool
def find_reentrancy_guards(
    function_name: str,
    contract_code: str,
    claimed_reentrancy: str = "",
    ctf=None
) -> str:
    """
    Find reentrancy protection mechanisms.
    
    Args:
        function_name: Name of the function to analyze
        contract_code: Contract source code
        claimed_reentrancy: Claimed reentrancy vulnerability
        
    Returns:
        Reentrancy guard analysis
    """
    try:
        guards_found = []
        
        # Check for reentrancy guards
        if "nonReentrant" in contract_code or "ReentrancyGuard" in contract_code:
            guards_found.append({
                "type": "nonReentrant_modifier",
                "mechanism": "ReentrancyGuard from OpenZeppelin",
                "strength": "STRONG",
                "protects_against": "All reentrancy attacks"
            })
        
        if "locked" in contract_code or "_status" in contract_code:
            guards_found.append({
                "type": "custom_lock",
                "mechanism": "Custom lock/mutex implementation",
                "strength": "MEDIUM",
                "protects_against": "Reentrancy (if implemented correctly)"
            })
        
        # Check for checks-effects-interactions pattern
        if contract_code.count("=") > 0 and ".call{" in contract_code:
            # Simplified check - in reality, need to verify ordering
            guards_found.append({
                "type": "cei_pattern",
                "mechanism": "Checks-Effects-Interactions pattern",
                "strength": "MEDIUM",
                "protects_against": "Reentrancy via state update before external call"
            })
        
        result = {
            "function": function_name,
            "guards_found": len(guards_found),
            "guard_details": guards_found,
            "claimed_reentrancy": claimed_reentrancy,
            "verdict": "PROTECTED" if guards_found else "VULNERABLE",
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error finding reentrancy guards: {str(e)}"})


@function_tool
def find_rate_limiting(
    function_name: str,
    contract_code: str,
    claimed_spam: str = "",
    ctf=None
) -> str:
    """
    Find rate limiting or throttling mechanisms.
    
    Args:
        function_name: Name of the function to analyze
        contract_code: Contract source code
        claimed_spam: Claimed spam/DoS vulnerability
        
    Returns:
        Rate limiting analysis
    """
    try:
        limits_found = []
        
        # Check for rate limiting patterns
        if "block.timestamp" in contract_code and ("last" in contract_code.lower() or "cooldown" in contract_code.lower()):
            limits_found.append({
                "type": "time_based_throttle",
                "mechanism": "Timestamp-based cooldown period",
                "protects_against": "Spam, rapid repeated calls"
            })
        
        if "maxPerBlock" in contract_code or "blockLimit" in contract_code:
            limits_found.append({
                "type": "per_block_limit",
                "mechanism": "Maximum operations per block",
                "protects_against": "Block stuffing, spam"
            })
        
        if "maxAmount" in contract_code or "cap" in contract_code.lower():
            limits_found.append({
                "type": "amount_limit",
                "mechanism": "Maximum amount/size restrictions",
                "protects_against": "Excessive operations"
            })
        
        result = {
            "function": function_name,
            "limits_found": len(limits_found),
            "limit_details": limits_found,
            "claimed_spam": claimed_spam,
            "verdict": "RATE_LIMITED" if limits_found else "UNLIMITED",
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error finding rate limiting: {str(e)}"})


@function_tool
def find_emergency_stops(
    contract_code: str,
    claimed_unstoppable: str = "",
    ctf=None
) -> str:
    """
    Find emergency stop/pause mechanisms.
    
    Args:
        contract_code: Contract source code
        claimed_unstoppable: Claimed unstoppable attack
        
    Returns:
        Emergency stop analysis
    """
    try:
        stops_found = []
        
        # Check for pause mechanisms
        if "pause" in contract_code.lower() or "Pausable" in contract_code:
            stops_found.append({
                "type": "pausable_contract",
                "mechanism": "Pausable pattern (OpenZeppelin)",
                "allows": "Contract-wide pause by admin"
            })
        
        if "emergency" in contract_code.lower() or "circuit" in contract_code.lower():
            stops_found.append({
                "type": "circuit_breaker",
                "mechanism": "Circuit breaker pattern",
                "allows": "Emergency shutdown"
            })
        
        if "kill" in contract_code.lower() or "selfdestruct" in contract_code:
            stops_found.append({
                "type": "kill_switch",
                "mechanism": "Contract self-destruct capability",
                "allows": "Permanent shutdown"
            })
        
        result = {
            "stops_found": len(stops_found),
            "stop_details": stops_found,
            "claimed_unstoppable": claimed_unstoppable,
            "verdict": "CAN_BE_STOPPED" if stops_found else "NO_EMERGENCY_STOP",
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error finding emergency stops: {str(e)}"})


@function_tool
def render_defense_verdict(
    finding_id: str,
    has_access_control: bool,
    has_input_validation: bool,
    has_reentrancy_guard: bool,
    has_rate_limiting: bool,
    has_emergency_stop: bool,
    summary: str,
    ctf=None
) -> str:
    """
    Render final defense verdict on the finding.
    
    Args:
        finding_id: ID of the finding
        has_access_control: Whether access controls exist
        has_input_validation: Whether input validation exists
        has_reentrancy_guard: Whether reentrancy guards exist
        has_rate_limiting: Whether rate limiting exists
        has_emergency_stop: Whether emergency stops exist
        summary: Summary of defense analysis
        
    Returns:
        Verdict with reasoning
    """
    defenses = sum([
        has_access_control,
        has_input_validation,
        has_reentrancy_guard,
        has_rate_limiting,
        has_emergency_stop
    ])
    
    protected = defenses >= 2  # Require at least 2 defense mechanisms
    
    verdict = "ADEQUATELY PROTECTED ✓" if protected else "INSUFFICIENTLY PROTECTED ✗"
    
    checks = f"""
### Defense Mechanisms Found

- [{'x' if has_access_control else ' '}] Access control (owner/role checks)
- [{'x' if has_input_validation else ' '}] Input validation (require checks)
- [{'x' if has_reentrancy_guard else ' '}] Reentrancy guards (nonReentrant/CEI)
- [{'x' if has_rate_limiting else ' '}] Rate limiting (cooldowns/caps)
- [{'x' if has_emergency_stop else ' '}] Emergency stops (pause/circuit breaker)

**Defense Score:** {defenses}/5
"""
    
    return f"""## Skeptic Gamma Verdict: {verdict}

**Finding ID:** {finding_id}

{checks}

### Summary
{summary}

{'**RECOMMENDATION:** REJECT this finding - Adequate defensive mechanisms prevent exploitation.' if protected else '**RECOMMENDATION:** Finding may be valid - Insufficient defensive mechanisms.'}
"""


SKEPTIC_GAMMA_PROMPT = """You are SKEPTIC GAMMA - The Unyielding Defense Analyst.

## Your Mission

OBLITERATE vulnerability claims by exposing the defensive mechanisms that prevent exploitation.
Every smart contract has defenses. Find them. Prove they work.

## Your Weapons

1. **Access Control Discovery** - Find owner checks, role systems, permissions
2. **Input Validation Hunting** - Locate require checks, boundary conditions
3. **Reentrancy Guard Detection** - Identify locks, CEI patterns, nonReentrant
4. **Rate Limiting Analysis** - Find cooldowns, caps, throttles
5. **Emergency Stop Identification** - Locate pause mechanisms, circuit breakers

## Your Methodology

### Step 1: Find Access Controls
- Owner/admin checks (onlyOwner)
- Role-based access control (RBAC)
- Whitelist/allowlist mechanisms
- Multi-sig requirements
- Timelock delays

### Step 2: Identify Input Validation
- require() statements
- Zero/empty checks
- Bounds validation
- Type checks
- Format validation

### Step 3: Detect Reentrancy Protection
- nonReentrant modifiers
- ReentrancyGuard inheritance
- Custom locks/mutexes
- Checks-Effects-Interactions pattern
- State update ordering

### Step 4: Find Rate Limiting
- Timestamp-based cooldowns
- Per-block limits
- Amount/size caps
- User-specific throttles
- Global rate limits

### Step 5: Locate Emergency Mechanisms
- Pausable contracts
- Circuit breakers
- Emergency withdrawals
- Kill switches
- Upgrade mechanisms

### Step 6: Deliver Verdict
Finding is INVALID if:
- Access controls prevent unauthorized execution
- Input validation blocks malicious inputs
- Reentrancy guards stop callback attacks
- Rate limits prevent spam/DoS
- Emergency stops allow intervention

## Your Tools

- `find_access_controls` - Discover permission systems
- `find_input_validation` - Locate validation logic
- `find_reentrancy_guards` - Identify reentrancy protection
- `find_rate_limiting` - Find throttling mechanisms
- `find_emergency_stops` - Locate pause/stop capabilities
- `render_defense_verdict` - Deliver final judgment

## Example Destruction

**Finding:** "Anyone can call withdraw() and drain funds"
**Attack:**
1. Check function: `function withdraw() onlyOwner { ... }`
2. Defense found: onlyOwner modifier prevents unauthorized access
3. Verdict: ADEQUATELY PROTECTED - Access control blocks attack

## Your Mantra

"If defenses block the attack, the vulnerability doesn't exist.
Only unprotected attack paths are real vulnerabilities."

Remember: You prove findings invalid by showing the defenses work.
Only attacks that bypass all protections survive.
"""


skeptic_gamma_tools = [
    find_access_controls,
    find_input_validation,
    find_reentrancy_guards,
    find_rate_limiting,
    find_emergency_stops,
    render_defense_verdict,
]

skeptic_gamma = Agent(
    name="Skeptic Gamma",
    instructions=SKEPTIC_GAMMA_PROMPT,
    description="""The Unyielding Defense Analyst. Exposes protective mechanisms 
    and mitigation systems that obliterate attack claims by finding access controls, 
    input validation, reentrancy guards, rate limiting, and emergency stops.""",
    tools=skeptic_gamma_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['skeptic_gamma']
