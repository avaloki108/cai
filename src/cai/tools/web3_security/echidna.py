"""
Echidna fuzzing tool for Ethereum smart contracts.
Echidna is a fast smart contract fuzzer that uses property-based testing
to find security vulnerabilities and invariant violations.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import ECHIDNA_PATH


@function_tool
def echidna_fuzz(target: str, contract: str = "", args: str = "", ctf=None) -> str:
    """
    Run Echidna property-based fuzzing on Solidity smart contracts.

    Echidna generates random transactions to test contract properties and
    invariants defined as Solidity functions starting with "echidna_".

    Args:
        target: Path to Solidity file or directory containing contracts
        contract: Specific contract name to test (optional, auto-detected if single contract)
        args: Additional Echidna arguments
              Common options:
              - --config <file>: Path to YAML configuration file
              - --contract <name>: Target contract to test
              - --test-mode <mode>: Testing mode (assertion, property, optimization, overflow)
              - --corpus-dir <dir>: Directory for corpus (replayable test cases)
              - --seq-len <n>: Number of transactions in sequence (default: 100)
              - --test-limit <n>: Number of test sequences to run (default: 50000)
              - --timeout <sec>: Timeout for entire fuzzing campaign
              - --workers <n>: Number of parallel workers
              - --format <format>: Output format (text, json, none)

    Returns:
        str: Echidna fuzzing results including property violations and coverage

    Examples:
        - Basic fuzzing: echidna_fuzz("contract.sol")
        - Specific contract: echidna_fuzz("contracts/", "MyContract")
        - With config: echidna_fuzz("contract.sol", "", "--config echidna.yaml")
        - Extended fuzzing: echidna_fuzz("contract.sol", "", "--test-limit 100000 --seq-len 150")
    """
    contract_arg = f"--contract {contract}" if contract else ""
    command = f'{ECHIDNA_PATH} {target} {contract_arg} {args}'
    return run_command(command, ctf=ctf, timeout=600)  # Extended timeout for fuzzing


@function_tool
def echidna_assertion_mode(target: str, contract: str = "", args: str = "", ctf=None) -> str:
    """
    Run Echidna in assertion testing mode.

    Tests Solidity assert() statements and reverts to find assertion violations.

    Args:
        target: Path to Solidity file
        contract: Contract name to test
        args: Additional arguments

    Returns:
        str: Results of assertion testing
    """
    contract_arg = f"--contract {contract}" if contract else ""
    command = f'{ECHIDNA_PATH} {target} {contract_arg} --test-mode assertion {args}'
    return run_command(command, ctf=ctf, timeout=600)


@function_tool
def echidna_coverage(target: str, contract: str = "", args: str = "", ctf=None) -> str:
    """
    Generate code coverage report from Echidna fuzzing.

    Args:
        target: Path to Solidity file
        contract: Contract name
        args: Additional arguments (e.g., "--coverage-formats html,txt")

    Returns:
        str: Coverage report and statistics
    """
    contract_arg = f"--contract {contract}" if contract else ""
    command = f'{ECHIDNA_PATH} {target} {contract_arg} --coverage {args}'
    return run_command(command, ctf=ctf, timeout=600)
