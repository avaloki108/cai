"""
Slither static analysis tool for Solidity smart contracts.
Slither is a Solidity static analysis framework that detects vulnerabilities
and provides detailed information about contract structure.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import SLITHER_PATH


@function_tool
def slither_analyze(target: str, args: str = "", ctf=None) -> str:
    """
    Run Slither static analysis on Solidity smart contracts.

    Slither detects vulnerabilities and code quality issues in Solidity contracts.
    It can analyze single files, directories, or entire projects.

    Args:
        target: Path to Solidity file, directory, or project root to analyze
        args: Additional Slither arguments (e.g., "--detect reentrancy", "--print human-summary")
              Common options:
              - --detect <detector>: Run specific detector
              - --exclude <detector>: Exclude specific detector
              - --print <printer>: Use specific printer (human-summary, inheritance-graph, etc.)
              - --json <file>: Export results to JSON
              - --sarif <file>: Export results to SARIF format
              - --checklist: Generate audit checklist

    Returns:
        str: Slither analysis output including detected vulnerabilities and recommendations

    Examples:
        - Basic analysis: slither_analyze("/path/to/contract.sol")
        - With specific detector: slither_analyze("/path/to/contract.sol", "--detect reentrancy")
        - Generate report: slither_analyze("/path/to/project", "--print human-summary")
    """
    # Use configured path
    command = f'{SLITHER_PATH} {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def slither_check_upgradeability(target: str, proxy_address: str = "", args: str = "", ctf=None) -> str:
    """
    Check upgradeability issues in proxy contracts using Slither.

    Args:
        target: Path to the implementation contract
        proxy_address: Address of the proxy contract (optional)
        args: Additional arguments for upgradeability checks

    Returns:
        str: Analysis of upgradeability issues and risks
    """
    proxy_arg = f"--proxy {proxy_address}" if proxy_address else ""
    command = f'{SLITHER_PATH} --detect-upgradeability {proxy_arg} {args} {target}'
    return run_command(command, ctf=ctf)
