"""
WASP - Web3 Audit Security Platform

A comprehensive smart contract security audit orchestrator that integrates
multiple security tools and maps findings to OWASP SCSVS/SCSTG requirements.
"""

from typing import Optional, List
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import WASP_PATH


@function_tool
def wasp_audit(
    target: str,
    tools: Optional[str] = None,
    output_dir: Optional[str] = None,
    format: str = "markdown",
    severity: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run a comprehensive security audit on a smart contract or project.

    WASP orchestrates multiple security tools (Slither, Mythril, etc.) and
    maps findings to OWASP SCSVS security categories.

    Args:
        target: Path to contract file or project directory
        tools: Comma-separated list of tools to use (default: all available)
               Available: slither, mythril, securify, echidna, medusa, etc.
        output_dir: Directory for audit reports
        format: Output format - "markdown", "json", "html"
        severity: Minimum severity to report - "critical", "high", "medium", "low", "info"
        extra_args: Additional WASP arguments

    Returns:
        str: Comprehensive audit results with OWASP mapping

    Example:
        wasp_audit("./contracts", tools="slither,mythril", format="markdown")
    """
    args = ["audit"]

    if tools:
        args.append(f"--tools {tools}")

    if output_dir:
        args.append(f"--output {output_dir}")

    args.append(f"--format {format}")

    if severity:
        args.append(f"--severity {severity}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_quick(
    target: str,
    tool: str = "slither",
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run a quick scan with a single security tool.

    Args:
        target: Path to contract file or project directory
        tool: Tool to use - slither, mythril, securify, echidna, etc.
        extra_args: Additional arguments passed to the tool

    Returns:
        str: Quick scan results
    """
    args = ["quick", f"--tool {tool}"]

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_ai_analyze(
    target: str,
    model: Optional[str] = None,
    focus: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run AI-powered security analysis using Ollama or other LLM backends.

    Args:
        target: Path to contract file or project directory
        model: AI model to use (default: from config, e.g., "codellama")
        focus: Focus area - "reentrancy", "access", "logic", "economic", etc.
        extra_args: Additional arguments

    Returns:
        str: AI-powered security analysis with detailed explanations
    """
    args = ["ai-analyze"]

    if model:
        args.append(f"--model {model}")

    if focus:
        args.append(f"--focus {focus}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_gen_invariants(
    target: str,
    framework: str = "echidna",
    output: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Generate Echidna/Medusa invariant tests for a contract.

    Automatically generates property-based test invariants based on
    contract analysis and common vulnerability patterns.

    Args:
        target: Path to contract file
        framework: Testing framework - "echidna" or "medusa"
        output: Output file path for generated tests
        extra_args: Additional arguments

    Returns:
        str: Generated invariant test code
    """
    args = ["gen-invariants", f"--framework {framework}"]

    if output:
        args.append(f"--output {output}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_gen_spec(
    target: str,
    output: Optional[str] = None,
    rules: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Generate Certora CVL specification template for a contract.

    Creates a starting point for formal verification with Certora Prover
    based on contract structure and common properties.

    Args:
        target: Path to contract file
        output: Output file path for generated spec
        rules: Comma-separated list of rule types to generate
               Available: "balance", "access", "reentrancy", "invariant"
        extra_args: Additional arguments

    Returns:
        str: Generated CVL specification template
    """
    args = ["gen-spec"]

    if output:
        args.append(f"--output {output}")

    if rules:
        args.append(f"--rules {rules}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_categories(ctf=None) -> str:
    """
    List OWASP SCSVS security categories and their descriptions.

    Returns:
        str: List of OWASP SCSVS categories for smart contract security
    """
    command = f"{WASP_PATH} categories"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_tools(ctf=None) -> str:
    """
    List all supported security tools and their availability.

    Returns:
        str: List of supported tools with version and status
    """
    command = f"{WASP_PATH} tools"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_status(ctf=None) -> str:
    """
    Check status of all configured security tools.

    Returns:
        str: Status report showing installed tools and their versions
    """
    command = f"{WASP_PATH} status"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_pattern_scan(
    target: str,
    patterns: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Scan code against known vulnerability patterns.

    Uses a pattern database built from historical audits and known exploits.

    Args:
        target: Path to contract file or project directory
        patterns: Comma-separated pattern IDs to check (default: all)
        extra_args: Additional arguments

    Returns:
        str: Pattern match results with confidence scores
    """
    args = ["pattern-scan"]

    if patterns:
        args.append(f"--patterns {patterns}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_review(
    finding_id: str,
    status: str,
    comment: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Review findings and provide feedback to improve detection.

    Args:
        finding_id: ID of the finding to review
        status: Review status - "confirmed", "false_positive", "duplicate", "wontfix"
        comment: Optional comment explaining the review decision
        extra_args: Additional arguments

    Returns:
        str: Review confirmation
    """
    args = ["review", f"--id {finding_id}", f"--status {status}"]

    if comment:
        args.append(f'--comment "{comment}"')

    if extra_args:
        args.append(extra_args)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_learning_stats(ctf=None) -> str:
    """
    Show learning system statistics.

    Displays stats about learned patterns, false positive rates, and
    accuracy improvements over time.

    Returns:
        str: Learning system statistics
    """
    command = f"{WASP_PATH} learning-stats"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_watch(
    target: str,
    tools: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Watch for file changes and automatically re-run audits.

    Args:
        target: Path to project directory to watch
        tools: Comma-separated list of tools to run on changes
        extra_args: Additional arguments

    Returns:
        str: Watch mode output (runs continuously)
    """
    args = ["watch"]

    if tools:
        args.append(f"--tools {tools}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_dashboard(
    port: int = 8080,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Launch the web dashboard for viewing audit results.

    Args:
        port: Port to run dashboard on (default: 8080)
        extra_args: Additional arguments

    Returns:
        str: Dashboard startup message with URL
    """
    args = ["dashboard", f"--port {port}"]

    if extra_args:
        args.append(extra_args)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def wasp_init(
    project_dir: str = ".",
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Initialize a new WASP configuration file in the project.

    Creates wasp.yaml with default settings for the project.

    Args:
        project_dir: Project directory (default: current directory)
        extra_args: Additional arguments

    Returns:
        str: Initialization confirmation
    """
    args = ["init"]

    if extra_args:
        args.append(extra_args)

    if project_dir != ".":
        args.append(project_dir)

    command = f"{WASP_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)
