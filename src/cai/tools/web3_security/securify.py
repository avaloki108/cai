"""
Securify 2.5 security analyzer for Ethereum smart contracts.
Securify uses static analysis and semantic reasoning to detect
vulnerabilities and verify security properties.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import SECURIFY_PATH


@function_tool
def securify_analyze(target: str, args: str = "", ctf=None) -> str:
    """
    Run Securify static analysis on Solidity smart contracts.

    Securify performs automated security analysis using datalog-based
    static analysis to detect common vulnerabilities and compliance violations.

    Args:
        target: Path to Solidity file or directory to analyze
        args: Additional Securify arguments
              Common options:
              - --timeout <seconds>: Analysis timeout (default: 600)
              - --output-format <format>: Output format (text, json, xml)
              - --output-dir <dir>: Output directory for reports
              - --visualize: Generate visualization of analysis results
              - --compliance: Check compliance with security standards
              - --no-color: Disable colored output

    Returns:
        str: Securify analysis output with detected vulnerabilities and compliance issues

    Examples:
        - Basic analysis: securify_analyze("contract.sol")
        - With timeout: securify_analyze("contract.sol", "--timeout 300")
        - JSON output: securify_analyze("contract.sol", "--output-format json")
        - With visualization: securify_analyze("contract.sol", "--visualize --output-dir ./reports")
    """
    command = f'{SECURIFY_PATH} {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def securify_compliance_check(target: str, standard: str = "erc20", args: str = "", ctf=None) -> str:
    """
    Check smart contract compliance with specific standards using Securify.

    Args:
        target: Path to Solidity file to analyze
        standard: Standard to check compliance against (e.g., erc20, erc721)
        args: Additional arguments

    Returns:
        str: Compliance analysis results
    """
    command = f'{SECURIFY_PATH} --compliance --standard {standard} {args} {target}'
    return run_command(command, ctf=ctf)
