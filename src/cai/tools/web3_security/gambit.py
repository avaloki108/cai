"""
Gambit symbolic execution tool for Solidity smart contracts.
Gambit performs symbolic execution to find vulnerabilities and verify properties.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import GAMBIT_PATH


@function_tool
def gambit_analyze(target: str, args: str = "", ctf=None) -> str:
    """
    Run Gambit symbolic execution analysis on Solidity smart contracts.

    Gambit uses symbolic execution to explore contract behavior and find vulnerabilities.

    Args:
        target: Path to Solidity file or project directory to analyze
        args: Additional Gambit arguments (e.g., "--timeout 300", "--solver z3")
              Common options:
              - --timeout <seconds>: Analysis timeout
              - --solver <solver>: SMT solver to use (z3, cvc4, etc.)
              - --max-depth <depth>: Maximum exploration depth
              - --json: Output results in JSON format

    Returns:
        str: Gambit analysis output including found vulnerabilities and execution paths

    Examples:
        - Basic analysis: gambit_analyze("contract.sol")
        - With timeout: gambit_analyze("contract.sol", "--timeout 600")
        - JSON output: gambit_analyze("contract.sol", "--json")
    """
    command = f'{GAMBIT_PATH} analyze {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def gambit_verify_property(target: str, property_file: str, args: str = "", ctf=None) -> str:
    """
    Verify specific properties using Gambit symbolic execution.

    Args:
        target: Path to Solidity file to analyze
        property_file: Path to property specification file
        args: Additional arguments for property verification

    Returns:
        str: Property verification results
    """
    command = f'{GAMBIT_PATH} verify {property_file} {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def gambit_explore_paths(target: str, max_paths: int = 100, args: str = "", ctf=None) -> str:
    """
    Explore execution paths in a smart contract using Gambit.

    Args:
        target: Path to Solidity file to analyze
        max_paths: Maximum number of paths to explore
        args: Additional exploration arguments

    Returns:
        str: Path exploration results and coverage information
    """
    command = f'{GAMBIT_PATH} explore --max-paths {max_paths} {args} {target}'
    return run_command(command, ctf=ctf)