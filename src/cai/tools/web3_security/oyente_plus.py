"""
Oyente Plus symbolic execution tool for Ethereum smart contracts.
Oyente Plus performs symbolic execution to detect vulnerabilities like reentrancy, integer overflow, and more.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import OYENTE_PLUS_PATH


@function_tool
def oyente_analyze(target: str, args: str = "", ctf=None) -> str:
    """
    Run Oyente Plus symbolic execution analysis on Ethereum smart contracts.

    Oyente Plus detects vulnerabilities through symbolic execution and constraint solving.

    Args:
        target: Path to Solidity file, bytecode file, or contract address to analyze
        args: Additional Oyente arguments (e.g., "--timeout 300", "--depth 50")
              Common options:
              - --timeout <seconds>: Analysis timeout
              - --depth <depth>: Maximum execution depth
              - --gas <limit>: Gas limit for execution
              - --json: Output results in JSON format
              - --verbose: Enable verbose output

    Returns:
        str: Symbolic execution analysis results including detected vulnerabilities

    Examples:
        - Basic analysis: oyente_analyze("contract.sol")
        - With timeout: oyente_analyze("contract.sol", "--timeout 600")
        - JSON output: oyente_analyze("contract.sol", "--json")
        - Bytecode analysis: oyente_analyze("bytecode.bin")
    """
    command = f'{OYENTE_PLUS_PATH} {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def oyente_check_vulnerability(target: str, vuln_type: str, args: str = "", ctf=None) -> str:
    """
    Check for specific vulnerability types using Oyente Plus.

    Args:
        target: Path to contract to analyze
        vuln_type: Type of vulnerability to check (reentrancy, overflow, underflow, etc.)
        args: Additional arguments for targeted analysis

    Returns:
        str: Targeted vulnerability analysis results
    """
    command = f'{OYENTE_PLUS_PATH} --check {vuln_type} {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def oyente_compare_contracts(contract1: str, contract2: str, args: str = "", ctf=None) -> str:
    """
    Compare two smart contracts for behavioral differences using Oyente Plus.

    Args:
        contract1: Path to first contract
        contract2: Path to second contract
        args: Additional comparison arguments

    Returns:
        str: Contract comparison results highlighting differences
    """
    command = f'{OYENTE_PLUS_PATH} --compare {contract1} {contract2} {args}'
    return run_command(command, ctf=ctf)