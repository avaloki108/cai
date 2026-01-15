"""
Clorgetizer gas analysis tool for Solidity smart contracts.
Clorgetizer analyzes gas usage, identifies expensive operations, and suggests optimizations.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import CLORGETIZER_PATH


@function_tool
def clorgetizer_analyze(target: str, args: str = "", ctf=None) -> str:
    """
    Run Clorgetizer gas analysis on Solidity smart contracts.

    Clorgetizer identifies gas-intensive operations and provides optimization suggestions.

    Args:
        target: Path to Solidity file or project directory to analyze
        args: Additional Clorgetizer arguments (e.g., "--threshold 1000", "--format json")
              Common options:
              - --threshold <gas>: Minimum gas threshold for reporting
              - --format <format>: Output format (text, json, csv)
              - --optimize: Include optimization suggestions
              - --compare: Compare gas usage across versions

    Returns:
        str: Gas analysis report with expensive operations and optimization recommendations

    Examples:
        - Basic analysis: clorgetizer_analyze("contract.sol")
        - With threshold: clorgetizer_analyze("contract.sol", "--threshold 2000")
        - JSON output: clorgetizer_analyze("contract.sol", "--format json")
    """
    command = f'{CLORGETIZER_PATH} analyze {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def clorgetizer_compare_versions(old_version: str, new_version: str, args: str = "", ctf=None) -> str:
    """
    Compare gas usage between two versions of a smart contract.

    Args:
        old_version: Path to the old version of the contract
        new_version: Path to the new version of the contract
        args: Additional comparison arguments

    Returns:
        str: Gas usage comparison report
    """
    command = f'{CLORGETIZER_PATH} compare {old_version} {new_version} {args}'
    return run_command(command, ctf=ctf)


@function_tool
def clorgetizer_optimize(target: str, args: str = "", ctf=None) -> str:
    """
    Generate gas optimization suggestions for a smart contract.

    Args:
        target: Path to Solidity file to optimize
        args: Additional optimization arguments

    Returns:
        str: Optimization suggestions and estimated gas savings
    """
    command = f'{CLORGETIZER_PATH} optimize {args} {target}'
    return run_command(command, ctf=ctf)