"""
Certora Prover formal verification tool for Solidity smart contracts.
Certora Prover uses formal methods to mathematically prove contract properties and detect vulnerabilities.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import CERTORA_PROVER_PATH


@function_tool
def certora_verify(target: str, spec_file: str, args: str = "", ctf=None) -> str:
    """
    Run Certora Prover formal verification on Solidity smart contracts.

    Certora Prover mathematically proves properties and detects complex vulnerabilities.

    Args:
        target: Path to Solidity file or project directory to verify
        spec_file: Path to Certora specification file (.spec)
        args: Additional Certora arguments (e.g., "--solc solc8.0", "--optimistic_loop")
              Common options:
              - --solc <version>: Solidity compiler version
              - --optimistic_loop: Enable optimistic loop handling
              - --loop_iter <n>: Maximum loop iterations
              - --method <name>: Verify specific method
              - --rule <name>: Verify specific rule

    Returns:
        str: Formal verification results including proved/disproved properties

    Examples:
        - Basic verification: certora_verify("contract.sol", "spec.spec")
        - Specific method: certora_verify("contract.sol", "spec.spec", "--method transfer")
        - With compiler: certora_verify("contract.sol", "spec.spec", "--solc solc8.0")
    """
    command = f'{CERTORA_PROVER_PATH} {target} --verify {spec_file} {args}'
    return run_command(command, ctf=ctf)


@function_tool
def certora_run_tests(target: str, test_file: str, args: str = "", ctf=None) -> str:
    """
    Run Certora test scenarios on a smart contract.

    Args:
        target: Path to Solidity file to test
        test_file: Path to test specification file
        args: Additional test arguments

    Returns:
        str: Test execution results and coverage
    """
    command = f'{CERTORA_PROVER_PATH} {target} --run_tests {test_file} {args}'
    return run_command(command, ctf=ctf)


@function_tool
def certora_check_invariants(target: str, invariant_file: str, args: str = "", ctf=None) -> str:
    """
    Check contract invariants using Certora Prover.

    Args:
        target: Path to Solidity file to analyze
        invariant_file: Path to invariant specification file
        args: Additional invariant checking arguments

    Returns:
        str: Invariant verification results
    """
    command = f'{CERTORA_PROVER_PATH} {target} --check_invariants {invariant_file} {args}'
    return run_command(command, ctf=ctf)