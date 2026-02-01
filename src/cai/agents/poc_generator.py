"""
PoC Generator Agent

Specialized agent for generating Foundry-based Proof-of-Concept (PoC) exploits
for detected vulnerabilities.
"""

import os
from dotenv import load_dotenv
from typing import Dict, Any, List
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool

load_dotenv()

api_key = (
    os.getenv("OPENAI_API_KEY")
    or os.getenv("ANTHROPIC_API_KEY")
    or os.getenv("ZAI_API_KEY")
    or "sk-placeholder"
)

# Use the same model configuration as other agents
model = OpenAIChatCompletionsModel(
    model=os.getenv("AEGIS_MODEL_NAME", "gpt-4o"),
    openai_client=AsyncOpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    ),
)

POC_PROMPT = """
You are the Aegis PoC Generator - an elite exploit developer.
Your goal is to create a working Foundry test that proves a vulnerability exists.

## Input
You will receive:
1. Contract vulnerability description
2. Affected code snippets
3. Contract source code (context)

## Output
You must generate a complete, compilable Foundry test file (.t.sol).
The test must:
1. Set up the environment (deploy contracts, fund accounts)
2. Execute the exploit steps clearly
3. Assert that the exploit succeeded (e.g., attacker balance increased, strict invariant broken)

## Rules
- Use `forge-std/Test.sol`
- Name the test function `testExploit()`
- Add comments explaining *why* each step is necessary
- If you cannot create a full exploit, create a reproduction case that triggers the vulnerable condition

## Example Structure
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Target.sol";

contract ExploitTest is Test {
    Target target;
    address attacker = address(0xB33F);

    function setUp() public {
        target = new Target();
        // setup...
    }

    function testExploit() public {
        vm.startPrank(attacker);
        // attack...
        vm.stopPrank();
        
        // Assert impact
        assertGt(attacker.balance, 0);
    }
}
```
"""

poc_generator = Agent(
    name="poc_generator",
    model=model,
    instructions=POC_PROMPT,
    tools=[],  # Can add file reading tools if needed, but often context is passed in
)


@function_tool(strict_mode=False)
def generate_poc(
    finding: Dict[str, Any], 
    contract_code: str,
    ctf=None
) -> str:
    """
    Generate a Proof-of-Concept exploit test for a finding.
    
    Args:
        finding: Vulnerability finding dictionary (description, severity, etc.)
        contract_code: Source code of the affected contract
        
    Returns:
        String containing the generated Solidity test code.
    """
    # This acts as a wrapper to call the agent
    # In a real system, we might invoke the agent runner here.
    # For now, we'll return a prompt structure for the runner to execute, 
    # or if we are inside a tool, we might not be able to call another agent easily 
    # without the Runner infrastructure.
    
    # However, since this file DEFINES the agent, we can export the agent object
    # and let the Orchestrator or Audit command run it.
    
    return "Use the 'poc_generator' agent directly with the Runner."

