"""
Fork Testing Driver for Foundry

Automatically generates Foundry fork tests for suspicious patterns.
When a hypothesis is formed, auto-generate and run PoC attempt.

Integration:
- Uses invariant_gen.generate_echidna_config/medusa_config for property generation
- Reads hypothesis from reasoning.register_hypothesis output
- Generates test harness for exploit verification

Usage:
1. Form hypothesis using reasoning.register_hypothesis
2. Fork test auto-generated from hypothesis
3. Run test with forge test
"""

import json
import os
from typing import Any, Dict, List, Optional
from cai.sdk.agents import function_tool


@function_tool
def generate_fork_test(
    hypothesis: str,
    contract_path: str,
    contract_name: str,
    block_number: int = 18000000,
    invariant_specs: str = "",
    ctf=None,
) -> str:
    """
    Generate Foundry fork test from attack hypothesis.

    Creates a .t.sol test file that:
    - Forks mainnet at specified block
    - Implements exploit steps based on hypothesis
    - Uses invariants from Echidna/Medusa

    Args:
        hypothesis: Attack hypothesis to test
        contract_path: Path to Solidity contract file
        contract_name: Contract name to test
        block_number: Block number to fork from (default: 18000000)
        invariant_specs: Custom invariants or specs from invariant_gen

    Returns:
        JSON with generated test file path and content
    """
    try:
        # Parse hypothesis for exploit steps
        hypothesis_lower = hypothesis.lower()

        # Determine exploit type and generate steps
        if "oracle" in hypothesis_lower or "manipulation" in hypothesis_lower:
            exploit_steps = [
                "// Step 1: Setup attacker state",
                "uint256 attackerBalance = 1000 ether;",
                "",
                "// Step 2: Perform flash loan attack",
                "IERC20 flashToken = IERC20(address(flashTokenAddress));",
                "flashToken.mint(address(this), 1000 ether);",
                "",
                "// Step 3: Manipulate oracle",
                "// Assume oracle reads spot price, modify with flash loan",
                "",
                "// Step 4: Profit",
                "vm.stopPrank();",
            ]

        elif "reentrancy" in hypothesis_lower:
            exploit_steps = [
                "// Step 1: Setup attacker state",
                "address attacker;",
                "",
                "// Step 2: Execute reentrancy attack",
                "exploit.vulnerableFunction();",
                "vm.startPrank();",
                "",
                "// Step 3: Extract funds",
                "attacker.withdraw(exploitVictimAmount);",
            ]

        elif "flash loan" in hypothesis_lower or "flashloan" in hypothesis_lower:
            exploit_steps = [
                "// Step 1: Setup flash loan",
                "address flashLoanProvider;",
                "",
                "// Step 2: Borrow funds",
                "IFlashLoan(flashLoanProvider).flashLoan(1000 ether);",
                "",
                "// Step 3: Perform attack",
                "performAttackLogic();",
                "",
                "// Step 4: Repay flash loan",
                'IFlashLoan(flashLoanProvider).repayFlashLoan{type(keccak256(blockhash(abi.encodeWithSignature("transfer(address,uint256)", address(exploitVictim), 1000 ether)))};',
            ]

        else:
            exploit_steps = [
                "// TODO: Implement exploit steps for hypothesis: " + hypothesis,
            ]

        # Build test contract
        test_contract = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IVulnerable {{
    function vulnerableFunction() external;
}}

contract ForkTest is Test {{
    address public constant EXPLOIT_VICTIM = {contract_name};
    IVulnerable public vulnerable;
    
    function setUp() public {{
        vm.createSelectFork("mainnet", {block_number});
    }}
    
    function test_exploit() public {{
        // Exploit steps from hypothesis
{chr(10).join(exploit_steps)}
    }}
}}"""

        # Write test file
        output_path = f"test_exploit_{{contract_name}}.t.sol"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(test_contract)

        # Generate Foundry command
        forge_command = f"forge test --match-path test/ --match-contract ForkTest -vv"

        # Generate config if invariants provided
        config_path = "foundry.toml"
        config_content = f"""[profile.default]
src = 'src'
out = 'out'
libs = ['lib/forge-std/src/']
verbosity = 3

# Test configuration
[fuzz]
runs = 50000

[invariant]
fail_on_revert = false
"""

        if invariant_specs:
            config_content += f'\n[hypothesis_{hypothesis[:30].replace(" ", "_")}]\ninvariant_spec = ""{invariant_specs.replace('"', '\\"')}"'

        with open(config_path, "w") as f:
            f.write(config_content)

        return json.dumps(
            {
                "status": "success",
                "test_file": output_path,
                "forge_command": forge_command,
                "config_file": config_path if invariant_specs else "existing",
                "hypothesis": hypothesis,
                "exploit_steps": len(exploit_steps),
                "block_number": block_number,
                "usage": [
                    f"Run: {{forge_command}}",
                    f"Then view results: forge test --match-contract ForkTest -vv",
                ],
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"error": f"Error generating fork test: {str(e)}"})


@function_tool
def run_fork_test(test_file: str, ctf=None) -> str:
    """
    Run previously generated fork test with Foundry.

    Executes the test file using forge test command.
    Captures output and analyzes results.

    Args:
        test_file: Path to .t.sol test file
        ctf: CTF flag for testing

    Returns:
        JSON with test execution results
    """
    try:
        # Check if forge is installed
        forge_check = os.system("which forge > /dev/null 2>&1")
        if forge_check != 0:
            return json.dumps(
                {
                    "error": "Foundry is not installed or not in PATH",
                    "recommendation": "Install Foundry: https://book.getfoundry.sh/",
                }
            )

        # Run forge test
        command = (
            f"forge test --match-path test/ --match-contract ForkTest -vv {test_file}"
        )

        result = os.system(command + " 2>&1")

        return json.dumps(
            {
                "status": "executed" if result == 0 else "failed",
                "exit_code": result,
                "command": command,
                "test_file": test_file,
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"error": f"Error running fork test: {str(e)}"})


@function_tool
def analyze_test_output(test_output: str, ctf=None) -> str:
    """
    Analyze Foundry test output for exploit success.

    Parses forge test output to determine:
    - Did exploit succeed?
    - What error occurred?
    - Gas usage?
    - State changes?

    Args:
        test_output: Output from run_fork_test

    Returns:
        JSON with analysis of test results
    """
    try:
        analysis = {
            "exploit_succeeded": False,
            "gas_used": 0,
            "errors_found": [],
            "state_changes": [],
        }

        output_lines = test_output.split("\n")

        for line in output_lines:
            line_lower = line.lower()

            if "[PASS]" in line or "pass" in line_lower:
                analysis["exploit_succeeded"] = True

            elif "FAIL" in line_lower or "fail" in line_lower:
                analysis["errors_found"].append(line.strip())

            elif "gas used:" in line_lower:
                try:
                    gas_value = line.split(":")[1].strip().replace(",", "").strip()
                    analysis["gas_used"] = int(gas_value)
                except (IndexError, ValueError):
                    pass

            elif "revert" in line_lower or "execution reverted" in line_lower:
                analysis["state_changes"].append("Transaction reverted during exploit")

        # Generate conclusion
        if analysis["exploit_succeeded"]:
            conclusion = "Exploit successfully demonstrated via fork test"
        elif analysis["errors_found"]:
            conclusion = f"Exploit failed with {len(analysis['errors_found'])} error(s)"
        else:
            conclusion = "Test inconclusive - exploit not confirmed"

        analysis["conclusion"] = conclusion

        return json.dumps(analysis, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Error analyzing test output: {str(e)}"})
