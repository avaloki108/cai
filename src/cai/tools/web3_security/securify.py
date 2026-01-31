"""
Securify - Static Analyzer for Ethereum Smart Contracts

Securify uses static analysis and pattern matching to detect vulnerabilities
and verify security properties in Solidity smart contracts.
"""

from typing import Optional, List
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import SECURIFY_PATH


@function_tool
def securify_analyze(
    target: str,
    use_patterns: Optional[str] = None,
    exclude_patterns: Optional[str] = None,
    include_severity: Optional[str] = None,
    exclude_severity: Optional[str] = None,
    include_contracts: Optional[str] = None,
    exclude_contracts: Optional[str] = None,
    show_compliants: bool = False,
    solidity_path: Optional[str] = None,
    visualize: bool = False,
    ignore_pragma: bool = False,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Securify static analysis on Solidity smart contracts.

    Securify uses Datalog-based analysis to detect vulnerabilities
    through pattern matching against known security issues.

    Args:
        target: Path to Solidity file or contract address on blockchain
        use_patterns: Space-separated pattern names to include (default: all)
        exclude_patterns: Space-separated pattern names to exclude
        include_severity: Severity levels to include - CRITICAL, HIGH, MEDIUM, LOW, INFO
        exclude_severity: Severity levels to exclude
        include_contracts: Contract names to include in output
        exclude_contracts: Contract names to exclude from output
        show_compliants: Show compliant (safe) matches for debugging
        solidity_path: Path to Solidity compiler binary
        visualize: Generate AST visualization
        ignore_pragma: Ignore pragma version directives
        extra_args: Additional Securify arguments

    Returns:
        str: Analysis results with detected vulnerabilities

    Available Patterns:
        Critical: DAO, DAOConstantGas, MissingInputValidation,
                 UnrestrictedEtherFlow, UnhandledException
        High: TODAmount, TODReceiver, TODTransfer, UnrestrictedWrite,
              LockedEther, RepeatedCall
        Medium: UnusedReturn, ShadowedLocalVariable, MissingInputValidation
        Low: SolcVersion, AssemblyUsage, ERC20Interface
        Info: TxOrigin, HashCollision, StateVariableShadowing

    Examples:
        securify_analyze("contract.sol", include_severity="CRITICAL HIGH")
        securify_analyze("0x123...", from_blockchain=True)
    """
    args = [target]

    if use_patterns:
        args.append(f"-p {use_patterns}")

    if exclude_patterns:
        args.append(f"--exclude-patterns {exclude_patterns}")

    if include_severity:
        args.append(f"-i {include_severity}")

    if exclude_severity:
        args.append(f"-e {exclude_severity}")

    if include_contracts:
        args.append(f"-c {include_contracts}")

    if exclude_contracts:
        args.append(f"--exclude-contracts {exclude_contracts}")

    if show_compliants:
        args.append("--show-compliants")

    if solidity_path:
        args.append(f"--solidity {solidity_path}")

    if visualize:
        args.append("-v")

    if ignore_pragma:
        args.append("--ignore-pragma")

    if extra_args:
        args.append(extra_args)

    command = f"{SECURIFY_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def securify_from_blockchain(
    address: str,
    api_key_file: Optional[str] = None,
    include_severity: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Analyze a contract deployed on Ethereum blockchain.

    Fetches source code from Etherscan and runs Securify analysis.

    Args:
        address: Contract address on Ethereum (0x...)
        api_key_file: Path to file containing Etherscan API key
        include_severity: Minimum severity to report
        extra_args: Additional arguments

    Returns:
        str: Analysis results for on-chain contract

    Note: Requires Etherscan API key for verified contracts.
    """
    args = [address, "-b"]  # from-blockchain flag

    if api_key_file:
        args.append(f"-k {api_key_file}")

    if include_severity:
        args.append(f"-i {include_severity}")

    if extra_args:
        args.append(extra_args)

    command = f"{SECURIFY_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def securify_list_patterns(ctf=None) -> str:
    """
    List all available Securify security patterns.

    Returns:
        str: List of patterns with descriptions and severity levels
    """
    command = f"{SECURIFY_PATH} --list-patterns"
    return run_command(command, ctf=ctf)


@function_tool
def securify_compliance_check(
    target: str,
    standard: str = "erc20",
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Check smart contract compliance with ERC standards.

    Args:
        target: Path to Solidity file
        standard: Standard to check - "erc20", "erc721", "erc1155"
        extra_args: Additional arguments

    Returns:
        str: Compliance analysis showing missing or incorrect implementations
    """
    # Use appropriate patterns for standard compliance
    standard_patterns = {
        "erc20": "ERC20Interface",
        "erc721": "ERC721Interface",
        "erc1155": "ERC1155Interface",
    }

    pattern = standard_patterns.get(standard, "ERC20Interface")
    args = [target, f"-p {pattern}", "--show-compliants"]

    if extra_args:
        args.append(extra_args)

    command = f"{SECURIFY_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def securify_critical_only(
    target: str,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Securify with only critical severity patterns.

    Fast analysis focused on the most severe vulnerabilities:
    DAO attacks, unhandled exceptions, unrestricted ether flow.

    Args:
        target: Path to Solidity file
        extra_args: Additional arguments

    Returns:
        str: Critical vulnerability analysis results
    """
    args = [target, "-i CRITICAL"]

    if extra_args:
        args.append(extra_args)

    command = f"{SECURIFY_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def securify_with_interpreter(
    target: str,
    recompile: bool = False,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Securify using the Souffle interpreter.

    Useful when experimenting with new patterns or debugging
    the analysis. Slower but more flexible.

    Args:
        target: Path to Solidity file
        recompile: Force recompilation of Datalog code
        extra_args: Additional arguments

    Returns:
        str: Analysis results using interpreter mode
    """
    args = [target, "--interpreter"]

    if recompile:
        args.append("--recompile")

    if extra_args:
        args.append(extra_args)

    command = f"{SECURIFY_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def securify_visualize_ast(
    target: str,
    output_dir: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Generate AST visualization for the contract.

    Creates a visual representation of the Abstract Syntax Tree,
    useful for understanding contract structure.

    Args:
        target: Path to Solidity file
        output_dir: Directory to save visualization
        extra_args: Additional arguments

    Returns:
        str: Visualization generation result
    """
    args = [target, "-v"]  # visualize flag

    if extra_args:
        args.append(extra_args)

    command = f"{SECURIFY_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)
