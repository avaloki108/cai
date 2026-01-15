"""
Auditor Framework comprehensive smart contract auditing tool.
The Auditor Framework provides a unified interface for comprehensive smart contract security analysis.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import AUDITOR_FRAMEWORK_PATH


@function_tool
def auditor_run_audit(target: str, audit_type: str = "full", args: str = "", ctf=None) -> str:
    """
    Run comprehensive audit using the Auditor Framework.

    The Auditor Framework combines multiple analysis techniques for thorough security assessment.

    Args:
        target: Path to Solidity file, directory, or project to audit
        audit_type: Type of audit to perform (full, quick, deep, compliance)
        args: Additional Auditor Framework arguments (e.g., "--format json", "--timeout 1800")
              Common options:
              - --format <format>: Output format (json, html, pdf)
              - --timeout <seconds>: Audit timeout
              - --severity <level>: Minimum severity level to report
              - --exclude <checks>: Comma-separated list of checks to exclude
              - --config <file>: Custom configuration file

    Returns:
        str: Comprehensive audit report with findings, severity levels, and recommendations

    Examples:
        - Full audit: auditor_run_audit("contract.sol", "full")
        - Quick scan: auditor_run_audit("contract.sol", "quick")
        - JSON output: auditor_run_audit("contract.sol", "full", "--format json")
        - Project audit: auditor_run_audit("./project", "full")
    """
    command = f'{AUDITOR_FRAMEWORK_PATH} audit {audit_type} {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def auditor_check_compliance(target: str, standard: str, args: str = "", ctf=None) -> str:
    """
    Check compliance with specific standards using the Auditor Framework.

    Args:
        target: Path to contract or project to check
        standard: Compliance standard (erc20, erc721, erc1155, custom)
        args: Additional compliance check arguments

    Returns:
        str: Compliance assessment report
    """
    command = f'{AUDITOR_FRAMEWORK_PATH} compliance {standard} {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def auditor_generate_report(audit_data: str, format_type: str = "html", args: str = "", ctf=None) -> str:
    """
    Generate detailed audit reports from analysis data.

    Args:
        audit_data: Path to audit data file or directory
        format_type: Report format (html, pdf, json, markdown)
        args: Additional report generation arguments

    Returns:
        str: Generated report content or path to report file
    """
    command = f'{AUDITOR_FRAMEWORK_PATH} report {audit_data} --format {format_type} {args}'
    return run_command(command, ctf=ctf)


@function_tool
def auditor_scan_dependencies(target: str, args: str = "", ctf=None) -> str:
    """
    Scan and analyze contract dependencies for security issues.

    Args:
        target: Path to contract with dependencies to scan
        args: Additional dependency scanning arguments

    Returns:
        str: Dependency analysis report with vulnerabilities and recommendations
    """
    command = f'{AUDITOR_FRAMEWORK_PATH} dependencies {args} {target}'
    return run_command(command, ctf=ctf)