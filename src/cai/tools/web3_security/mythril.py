"""
Mythril - Security Analysis Tool for EVM Bytecode

Mythril uses symbolic execution, SMT solving, and taint analysis to detect
security vulnerabilities in Ethereum smart contracts.
"""

from typing import Optional
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import MYTHRIL_PATH
from .tool_cache import load_cached_result, save_cached_result



@function_tool
def mythril_analyze(
    target: str,
    solv: Optional[str] = None,
    output_format: str = "text",
    execution_timeout: int = 86400,
    create_timeout: int = 10,
    max_depth: int = 128,
    strategy: str = "bfs",
    solver_timeout: int = 25000,
    transaction_count: int = 2,
    modules: Optional[str] = None,
    rpc: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Mythril symbolic execution analysis on smart contracts.

    Mythril performs symbolic execution and SMT solving to detect vulnerabilities
    like integer overflows, reentrancy, unprotected functions, etc.

    Args:
        target: Path to Solidity file, bytecode file, or contract address
        solv: Solidity compiler version (e.g., "0.8.17")
        output_format: Output format - "text", "json", "markdown", "jsonv2"
        execution_timeout: Total execution timeout in seconds (default: 86400)
        create_timeout: Timeout for contract creation in seconds (default: 10)
        max_depth: Maximum recursion depth (default: 128)
        strategy: Search strategy - "bfs" (breadth-first) or "dfs" (depth-first)
        solver_timeout: SMT solver timeout in milliseconds (default: 25000)
        transaction_count: Number of transactions to explore (default: 2)
        modules: Comma-separated list of detection modules to run
        rpc: RPC endpoint for on-chain analysis
        extra_args: Additional Mythril arguments

    Returns:
        str: Mythril analysis output with detected vulnerabilities

    Detection Modules:
        - ether_thief: Detect unauthorized ether withdrawal
        - suicide: Detect unprotected selfdestruct
        - delegatecall: Detect dangerous delegatecall usage
        - state_change_external_calls: Detect reentrancy vulnerabilities
        - integer: Detect integer overflow/underflow
        - unchecked_retval: Detect unchecked return values
        - arbitrary_jump: Detect arbitrary jump vulnerabilities
        - exceptions: Detect assertion violations

    Examples:
        mythril_analyze("contract.sol", solv="0.8.17")
        mythril_analyze("0x...", rpc="https://eth-mainnet.alchemyapi.io/...")
    """
    args = ["analyze"]

    # Handle string "null" from JSON parsing - convert to None
    if isinstance(solv, str) and (solv.lower() == "null" or solv.strip() == ""):
        solv = None
    
    if isinstance(modules, str) and (modules.lower() == "null" or modules.strip() == ""):
        modules = None
    
    if isinstance(rpc, str) and (rpc.lower() == "null" or rpc.strip() == ""):
        rpc = None

    if solv:
        args.append(f"--solv {solv}")

    args.append(f"-o {output_format}")
    args.append(f"--execution-timeout {execution_timeout}")
    args.append(f"--create-timeout {create_timeout}")
    args.append(f"--max-depth {max_depth}")
    args.append(f"--strategy {strategy}")
    args.append(f"--solver-timeout {solver_timeout}")
    args.append(f"--transaction-count {transaction_count}")

    if modules:
        args.append(f"--modules {modules}")

    if rpc:
        args.append(f"--rpc {rpc}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    cache_args = {
        "solv": solv,
        "output_format": output_format,
        "execution_timeout": execution_timeout,
        "create_timeout": create_timeout,
        "max_depth": max_depth,
        "strategy": strategy,
        "solver_timeout": solver_timeout,
        "transaction_count": transaction_count,
        "modules": modules,
        "rpc": rpc,
        "extra_args": extra_args,
    }
    cached = load_cached_result("mythril", target, cache_args)
    if cached is not None:
        return cached

    command = f"{MYTHRIL_PATH} {' '.join(args)}"
    result = run_command(command, ctf=ctf)
    save_cached_result("mythril", target, cache_args, result)
    return result


@function_tool
def mythril_safe_functions(
    target: str,
    solv: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Check which functions are completely safe using symbolic execution.

    Identifies functions that have no detectable vulnerabilities and can be
    considered safe based on symbolic analysis.

    Args:
        target: Path to Solidity file or bytecode
        solv: Solidity compiler version
        extra_args: Additional arguments

    Returns:
        str: List of safe functions with analysis details
    """
    args = ["safe-functions"]

    if solv:
        args.append(f"--solv {solv}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{MYTHRIL_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def mythril_disassemble(
    target: str,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Disassemble EVM bytecode using Mythril.

    Args:
        target: Path to bytecode file or contract address
        extra_args: Additional arguments for disassembly

    Returns:
        str: Disassembled EVM bytecode with opcodes
    """
    args = ["disassemble"]

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{MYTHRIL_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def mythril_concolic(
    target: str,
    branches: str,
    solv: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run concolic execution to flip specific branches.

    Concolic (concrete + symbolic) execution helps explore specific code paths
    by providing concrete inputs that reach target branches.

    Args:
        target: Path to Solidity file or bytecode
        branches: Branch addresses to flip (comma-separated)
        solv: Solidity compiler version
        extra_args: Additional arguments

    Returns:
        str: Concolic execution results showing inputs to reach branches
    """
    args = ["concolic", f"--branches {branches}"]

    if solv:
        args.append(f"--solv {solv}")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{MYTHRIL_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def mythril_foundry(
    project_dir: str,
    contract: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Analyze a Foundry project with Mythril.

    Automatically detects and analyzes contracts in a Foundry project structure.

    Args:
        project_dir: Path to Foundry project directory
        contract: Specific contract to analyze (default: all)
        extra_args: Additional arguments

    Returns:
        str: Analysis results for the Foundry project
    """
    args = ["foundry"]

    if contract:
        args.append(f"--contract {contract}")

    if extra_args:
        args.append(extra_args)

    args.append(project_dir)

    command = f"{MYTHRIL_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def mythril_read_storage(
    address: str,
    position: str,
    rpc_url: str,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Read storage from a deployed contract using Mythril.

    Args:
        address: Contract address (0x...)
        position: Storage position/slot to read
        rpc_url: RPC endpoint URL
        extra_args: Additional arguments

    Returns:
        str: Storage value at specified position
    """
    args = ["read-storage", address, position, f"--rpc {rpc_url}"]

    if extra_args:
        args.append(extra_args)

    command = f"{MYTHRIL_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def mythril_list_detectors(ctf=None) -> str:
    """
    List available Mythril detection modules.

    Returns:
        str: List of available detection modules with descriptions
    """
    command = f"{MYTHRIL_PATH} list-detectors"
    return run_command(command, ctf=ctf)


@function_tool
def mythril_function_to_hash(
    signature: str,
    ctf=None
) -> str:
    """
    Calculate the function selector hash from a function signature.

    Args:
        signature: Function signature (e.g., "transfer(address,uint256)")

    Returns:
        str: 4-byte function selector hash
    """
    command = f'{MYTHRIL_PATH} function-to-hash "{signature}"'
    return run_command(command, ctf=ctf)
