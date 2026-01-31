"""
Slitheryn - Enhanced Slither static analysis with AI-powered detection.

Slitheryn extends Slither with additional detectors, AI analysis capabilities,
and enhanced reporting. Supports multiple networks and compilation frameworks.
"""

import os
from typing import Optional, List
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import SLITHERYN_PATH


def _validate_target(target: str) -> Optional[str]:
    """Validate target parameter and return error message if invalid."""
    if not target or not target.strip():
        return "ERROR: target parameter is required. Please provide a path to a Solidity file or project directory."
    
    # Allow on-chain addresses (0x...) and network:address format
    if target.startswith("0x") or ":" in target:
        return None
    
    if not os.path.exists(target):
        return f"ERROR: Target path does not exist: {target}"
    
    return None


@function_tool
def slitheryn_analyze(
    target: str,
    detectors: Optional[str] = None,
    exclude_detectors: Optional[str] = None,
    exclude_dependencies: bool = True,
    exclude_low: bool = False,
    exclude_medium: bool = False,
    exclude_informational: bool = False,
    json_output: Optional[str] = None,
    sarif_output: Optional[str] = None,
    checklist: bool = False,
    filter_paths: Optional[str] = None,
    solc_version: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Slitheryn enhanced static analysis on Solidity smart contracts.

    Slitheryn provides comprehensive vulnerability detection with 80+ detectors
    covering reentrancy, access control, arithmetic issues, and more.

    Args:
        target: Path to Solidity file, project directory, or on-chain address.
                This is REQUIRED. Supports: file.sol, project_dir, 0x..., NETWORK:0x...
                Networks: mainnet, sepolia, polygon, arbitrum, optimism, base, etc.
        detectors: Comma-separated list of detectors to run (default: all)
                  Examples: "reentrancy-eth,arbitrary-send-eth,unchecked-transfer"
        exclude_detectors: Comma-separated list of detectors to exclude
        exclude_dependencies: Exclude results from dependencies (default: True)
        exclude_low: Exclude low severity findings
        exclude_medium: Exclude medium severity findings
        exclude_informational: Exclude informational findings
        json_output: Path to export results as JSON
        sarif_output: Path to export results as SARIF
        checklist: Generate markdown audit checklist
        filter_paths: Regex to exclude paths (e.g., "mocks/|test/")
        solc_version: Force specific Solidity compiler version (e.g., "0.8.22")
                     Use this when the contract pragma doesn't match your system solc.
        extra_args: Additional Slitheryn CLI arguments

    Returns:
        str: Analysis results with detected vulnerabilities

    Available Detectors (partial list):
        High Impact: arbitrary-send-eth, reentrancy-eth, controlled-delegatecall,
                    suicidal, unprotected-upgrade, unchecked-transfer
        Medium Impact: reentrancy-no-eth, locked-ether, incorrect-equality,
                      divide-before-multiply, shadowing-state
        Low Impact: naming-convention, dead-code, cache-array-length

    Examples:
        - Basic: slitheryn_analyze("/path/to/contract.sol")
        - With solc: slitheryn_analyze("/path/to/contract.sol", solc_version="0.8.22")
        - Specific detectors: slitheryn_analyze(target, detectors="reentrancy-eth,arbitrary-send-eth")
    """
    # Validate target
    error = _validate_target(target)
    if error:
        return error

    # Build command - target comes FIRST
    cmd_parts = [SLITHERYN_PATH, target]

    if detectors:
        cmd_parts.append(f"--detect {detectors}")

    if exclude_detectors:
        cmd_parts.append(f"--exclude {exclude_detectors}")

    if exclude_dependencies:
        cmd_parts.append("--exclude-dependencies")

    if exclude_low:
        cmd_parts.append("--exclude-low")

    if exclude_medium:
        cmd_parts.append("--exclude-medium")

    if exclude_informational:
        cmd_parts.append("--exclude-informational")

    if json_output:
        cmd_parts.append(f"--json {json_output}")

    if sarif_output:
        cmd_parts.append(f"--sarif {sarif_output}")

    if checklist:
        cmd_parts.append("--checklist")

    if filter_paths:
        cmd_parts.append(f"--filter-paths {filter_paths}")

    if solc_version:
        cmd_parts.append(f"--solc-solcs-select {solc_version}")

    if extra_args:
        cmd_parts.append(extra_args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def slitheryn_ai_analyze(
    target: str,
    model: str = "codex",
    contracts: Optional[str] = None,
    temperature: float = 0.0,
    solc_version: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run AI-powered security analysis using Slitheryn's Codex/AI integration.

    Uses OpenAI Codex or compatible models to analyze code for vulnerabilities
    that static analysis might miss.

    Args:
        target: Path to Solidity file or project directory (REQUIRED)
        model: AI model to use (default: "codex", or "text-davinci-003")
        contracts: Comma-separated list of contract names to analyze
        temperature: Model temperature (0.0 = precise, 1.0 = creative)
        solc_version: Solidity compiler version to use
        extra_args: Additional arguments

    Returns:
        str: AI-powered analysis results

    Note: Requires OPENAI_API_KEY environment variable to be set.
    """
    error = _validate_target(target)
    if error:
        return error

    cmd_parts = [SLITHERYN_PATH, target, "--codex"]

    if contracts:
        cmd_parts.append(f"--codex-contracts {contracts}")

    cmd_parts.append(f"--codex-model {model}")
    cmd_parts.append(f"--codex-temperature {temperature}")

    if solc_version:
        cmd_parts.append(f"--solc-solcs-select {solc_version}")

    if extra_args:
        cmd_parts.append(extra_args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def slitheryn_print(
    target: str,
    printer: str,
    include_interfaces: bool = False,
    solc_version: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Generate contract information using Slitheryn printers.

    Args:
        target: Path to Solidity file or project directory (REQUIRED)
        printer: Printer to use. Available printers:
                 - cfg: Control flow graph
                 - call-graph: Call graph visualization
                 - contract-summary: Contract summary
                 - function-summary: Function summary
                 - human-summary: Human-readable summary
                 - inheritance: Inheritance analysis
                 - inheritance-graph: Inheritance graph
                 - data-dependency: Data dependency analysis
                 - vars-and-auth: Variables and authorization
                 - echidna: Generate Echidna config
                 - evm: EVM representation
                 - slithir: SlithIR intermediate representation
                 - modifiers: Modifier analysis
                 - require: Require statement analysis
                 - dominator: Dominator tree
                 - halstead: Halstead complexity metrics
                 - martin: Martin metrics (coupling)
                 - loc: Lines of code
                 - ck: Chidamber and Kemerer metrics
        include_interfaces: Include interfaces in inheritance graph
        solc_version: Solidity compiler version to use
        extra_args: Additional arguments

    Returns:
        str: Printer output
    """
    error = _validate_target(target)
    if error:
        return error

    cmd_parts = [SLITHERYN_PATH, target, f"--print {printer}"]

    if include_interfaces:
        cmd_parts.append("--include-interfaces")

    if solc_version:
        cmd_parts.append(f"--solc-solcs-select {solc_version}")

    if extra_args:
        cmd_parts.append(extra_args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def slitheryn_list_detectors(ctf=None) -> str:
    """
    List all available Slitheryn detectors with descriptions.

    Returns:
        str: List of detectors with their impact levels and descriptions
    """
    command = f"{SLITHERYN_PATH} --list-detectors"
    return run_command(command, ctf=ctf)


@function_tool
def slitheryn_list_printers(ctf=None) -> str:
    """
    List all available Slitheryn printers.

    Returns:
        str: List of printers with descriptions
    """
    command = f"{SLITHERYN_PATH} --list-printers"
    return run_command(command, ctf=ctf)


@function_tool
def slitheryn_triage(
    target: str,
    database: str = "slitheryn.db.json",
    solc_version: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Slitheryn in triage mode to interactively manage findings.

    Triage mode allows marking findings as false positives or acknowledged,
    storing decisions in a database for future runs.

    Args:
        target: Path to Solidity file or project directory (REQUIRED)
        database: Path to triage database file (default: slitheryn.db.json)
        solc_version: Solidity compiler version to use
        extra_args: Additional arguments

    Returns:
        str: Triage session results
    """
    error = _validate_target(target)
    if error:
        return error

    cmd_parts = [
        SLITHERYN_PATH,
        target,
        "--triage-mode",
        f"--triage-database {database}",
    ]

    if solc_version:
        cmd_parts.append(f"--solc-solcs-select {solc_version}")

    if extra_args:
        cmd_parts.append(extra_args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def slitheryn_from_etherscan(
    address: str,
    network: str = "mainnet",
    api_key: Optional[str] = None,
    export_dir: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Analyze a contract from Etherscan or other block explorers.

    Args:
        address: Contract address (0x...) - REQUIRED
        network: Network name. Supported: mainnet, sepolia, polygon, amoy.pol,
                 arbitrum, sepolia.arb, optimism, sepolia.opti, base, sepolia.bas,
                 avalanche, bsc, etc.
        api_key: Block explorer API key (or set ETHERSCAN_API_KEY env var)
        export_dir: Directory to save downloaded sources
        extra_args: Additional arguments

    Returns:
        str: Analysis results for the on-chain contract

    Example:
        slitheryn_from_etherscan("0x1234...", network="polygon", api_key="YOUR_KEY")
    """
    if not address or not address.strip():
        return "ERROR: address parameter is required."

    if not address.startswith("0x"):
        return f"ERROR: Invalid address format. Expected 0x..., got: {address}"

    target = f"{network}:{address}" if network != "mainnet" else address

    cmd_parts = [SLITHERYN_PATH, target]

    if api_key:
        cmd_parts.append(f"--etherscan-apikey {api_key}")

    if export_dir:
        cmd_parts.append(f"--etherscan-export-directory {export_dir}")

    if extra_args:
        cmd_parts.append(extra_args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def slitheryn_foundry(
    project_dir: str,
    compile_all: bool = False,
    out_directory: Optional[str] = None,
    solc_version: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Analyze a Foundry project with Slitheryn.

    Args:
        project_dir: Path to Foundry project root (containing foundry.toml) - REQUIRED
        compile_all: Include test and script files in analysis
        out_directory: Custom Foundry output directory (default: out)
        solc_version: Solidity compiler version to use
        extra_args: Additional arguments

    Returns:
        str: Analysis results for the Foundry project
    """
    error = _validate_target(project_dir)
    if error:
        return error

    cmd_parts = [SLITHERYN_PATH, project_dir]

    if compile_all:
        cmd_parts.append("--foundry-compile-all")

    if out_directory:
        cmd_parts.append(f"--foundry-out-directory {out_directory}")

    if solc_version:
        cmd_parts.append(f"--solc-solcs-select {solc_version}")

    if extra_args:
        cmd_parts.append(extra_args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def slitheryn_hardhat(
    project_dir: str,
    ignore_compile: bool = False,
    cache_dir: Optional[str] = None,
    artifacts_dir: Optional[str] = None,
    solc_version: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Analyze a Hardhat project with Slitheryn.

    Args:
        project_dir: Path to Hardhat project root - REQUIRED
        ignore_compile: Skip Hardhat compilation (use existing artifacts)
        cache_dir: Custom cache directory (default: ./cache)
        artifacts_dir: Custom artifacts directory (default: ./artifacts)
        solc_version: Solidity compiler version to use
        extra_args: Additional arguments

    Returns:
        str: Analysis results for the Hardhat project
    """
    error = _validate_target(project_dir)
    if error:
        return error

    cmd_parts = [SLITHERYN_PATH, project_dir]

    if ignore_compile:
        cmd_parts.append("--hardhat-ignore-compile")

    if cache_dir:
        cmd_parts.append(f"--hardhat-cache-directory {cache_dir}")

    if artifacts_dir:
        cmd_parts.append(f"--hardhat-artifacts-directory {artifacts_dir}")

    if solc_version:
        cmd_parts.append(f"--solc-solcs-select {solc_version}")

    if extra_args:
        cmd_parts.append(extra_args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
